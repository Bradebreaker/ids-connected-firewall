"""
firewall/manager.py — iptables firewall rule management.

Provides async methods to add, remove, and list iptables rules.
Uses a custom chain (IDS_FIREWALL) inserted into INPUT so we never
accidentally flush the host's own rules.

All operations include a whitelist safety check as a last line of defence.

Requires root privileges.
"""

import asyncio
import logging
from typing import List, Optional

from config import settings, IS_LINUX
from db.models import FirewallRule

logger = logging.getLogger("ids.firewall")


class FirewallManager:
    """
    Manages iptables rules via async subprocess calls.

    Architecture:
        - Creates a custom chain (IDS_FIREWALL) on init.
        - Inserts a jump rule in INPUT → IDS_FIREWALL.
        - All IDS rules are added/removed in the custom chain.
        - The INPUT chain is never flushed directly.
    """

    def __init__(self):
        self.chain = settings.IPTABLES_CHAIN
        self.whitelist = set(settings.WHITELIST_IPS)

    async def _run(self, *args: str) -> tuple:
        """
        Run an iptables command asynchronously.

        Returns (returncode, stdout, stderr).
        On Windows, logs the command and returns a no-op success.
        """
        cmd = ["iptables"] + list(args)
        logger.debug("iptables command: %s", " ".join(cmd))

        if not IS_LINUX:
            logger.info("[Windows] iptables skipped: %s", " ".join(cmd))
            return 0, "", ""

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode().strip(), stderr.decode().strip()

    async def init_chain(self):
        """
        Create the custom chain and insert the jump rule if not present.

        Called once on application startup.
        """
        # Create the custom chain (ignore error if it already exists)
        rc, _, _ = await self._run("-N", self.chain)
        if rc == 0:
            logger.info("Created iptables chain: %s", self.chain)
        else:
            logger.info("Chain %s already exists", self.chain)

        # Check if jump rule already exists in INPUT
        rc, stdout, _ = await self._run("-L", "INPUT", "-n", "--line-numbers")
        if self.chain not in stdout:
            # Insert jump at position 1 (top of INPUT)
            await self._run("-I", "INPUT", "1", "-j", self.chain)
            logger.info("Inserted jump rule: INPUT → %s", self.chain)

    def _is_whitelisted(self, ip: str) -> bool:
        """Last-resort safety check before any block operation."""
        if ip in self.whitelist:
            logger.critical(
                "SAFETY: Refusing to block whitelisted IP %s", ip
            )
            return True
        return False

    async def add_rule(self, rule: FirewallRule) -> bool:
        """
        Add a firewall rule to iptables.

        Args:
            rule: FirewallRule ORM object with source_ip, dest_port, protocol, action.

        Returns:
            True if the rule was added, False if blocked by whitelist.
        """
        if self._is_whitelisted(rule.source_ip):
            return False

        cmd = ["-A", self.chain]

        # Source IP
        cmd.extend(["-s", rule.source_ip])

        # Protocol (optional)
        if rule.protocol:
            cmd.extend(["-p", rule.protocol])

        # Destination port (only if protocol supports ports)
        if rule.dest_port and rule.protocol in ("tcp", "udp"):
            cmd.extend(["--dport", str(rule.dest_port)])

        # Action (DROP or ACCEPT)
        cmd.extend(["-j", rule.action])

        rc, _, stderr = await self._run(*cmd)
        if rc != 0:
            logger.error("Failed to add iptables rule: %s", stderr)
            return False

        logger.info(
            "iptables rule added: %s %s %s (port %s, proto %s)",
            rule.action, rule.source_ip, rule.dest_port, rule.protocol, rule.action,
        )
        return True

    async def remove_rule(self, rule: FirewallRule) -> bool:
        """
        Remove a firewall rule from iptables.

        Mirrors the add_rule logic but uses -D instead of -A.
        """
        cmd = ["-D", self.chain]
        cmd.extend(["-s", rule.source_ip])

        if rule.protocol:
            cmd.extend(["-p", rule.protocol])

        if rule.dest_port and rule.protocol in ("tcp", "udp"):
            cmd.extend(["--dport", str(rule.dest_port)])

        cmd.extend(["-j", rule.action])

        rc, _, stderr = await self._run(*cmd)
        if rc != 0:
            logger.warning("Failed to remove iptables rule (may not exist): %s", stderr)
            return False

        logger.info(
            "iptables rule removed: %s %s (port %s)",
            rule.action, rule.source_ip, rule.dest_port,
        )
        return True

    async def list_current_rules(self) -> str:
        """Return the current iptables rules for our chain as a string."""
        rc, stdout, stderr = await self._run("-L", self.chain, "-n", "--line-numbers", "-v")
        if rc != 0:
            logger.error("Failed to list iptables rules: %s", stderr)
            return ""
        return stdout

    async def flush_chain(self):
        """
        Flush all rules in our custom chain.

        Used during reconciliation to rebuild from the DB state.
        """
        rc, _, stderr = await self._run("-F", self.chain)
        if rc != 0:
            logger.error("Failed to flush chain %s: %s", self.chain, stderr)
        else:
            logger.info("Flushed iptables chain: %s", self.chain)

    async def remove_rule_by_ip(self, ip: str) -> bool:
        """
        Remove all rules for a given IP from the custom chain.

        Used when manually unblocking an IP — removes any matching rule
        regardless of port/protocol.
        """
        # List rules and find matching line numbers
        rc, stdout, _ = await self._run("-L", self.chain, "-n", "--line-numbers")
        if rc != 0:
            return False

        # Parse line numbers for this IP (process in reverse to avoid index shift)
        lines_to_delete = []
        for line in stdout.split("\n"):
            if ip in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    lines_to_delete.append(int(parts[0]))

        # Delete in reverse order to preserve line numbering
        for line_num in sorted(lines_to_delete, reverse=True):
            await self._run("-D", self.chain, str(line_num))
            logger.info("Removed iptables rule at line %d for IP %s", line_num, ip)

        return len(lines_to_delete) > 0
