"""
detection/brute_force.py — Brute-force login attempt detection.

Monitors connection attempts to sensitive ports (SSH, RDP, FTP, Telnet)
and flags source IPs that exceed a threshold within a sliding time window.

Uses collections.deque per (source_ip, dest_port) pair.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Optional

from detection.base import BaseDetector
from db.schemas import AlertEvent
from config import settings

logger = logging.getLogger("ids.detection.brute_force")

# Map port numbers to service names for clearer alert descriptions
_PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
}


class BruteForceDetector(BaseDetector):
    """
    Detects brute-force login attempts against sensitive services.

    Algorithm:
        1. Only inspect TCP SYN packets to ports in the sensitive-port list.
        2. Track connection attempts per (source_ip, dest_port) in sliding window.
        3. If attempts >= threshold in the window, raise an alert.

    Severity scaling:
        - threshold .. 2×threshold  → medium
        - > 2×threshold             → high
    """

    name = "BruteForceDetector"

    def __init__(self):
        # { (source_ip, dest_port): deque of timestamps }
        self._windows: dict = defaultdict(deque)
        self._alerted: dict = {}  # {(source_ip, dest_port): last_alert_ts}
        self.threshold      = settings.BRUTE_FORCE_THRESHOLD
        self.window         = settings.BRUTE_FORCE_WINDOW
        self.sensitive_ports = set(settings.BRUTE_FORCE_PORTS)
        logger.info(
            "BruteForceDetector initialised: threshold=%d attempts in %ds, ports=%s",
            self.threshold, self.window, self.sensitive_ports,
        )

    def _evict_old(self, key: tuple, now: float):
        """Evict entries outside the sliding window."""
        dq = self._windows[key]
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        """Inspect TCP packets to sensitive ports for brute-force patterns."""
        src_ip   = packet_data.get("source_ip")
        dst_port = packet_data.get("dest_port")
        protocol = packet_data.get("protocol", "")
        flags    = packet_data.get("tcp_flags", "")

        # We only care about TCP connections to sensitive ports
        if not src_ip or dst_port is None:
            return None
        if protocol != "TCP":
            return None
        if dst_port not in self.sensitive_ports:
            return None

        # Only count SYN packets (new connection attempts)
        # Scapy represents flags like 'S', 'SA', 'FA', etc.
        if "S" not in str(flags):
            return None

        now = packet_data.get("timestamp", time.time())
        key = (src_ip, dst_port)

        # Record this attempt
        self._windows[key].append(now)
        self._evict_old(key, now)

        attempt_count = len(self._windows[key])

        if attempt_count < self.threshold:
            return None

        # Avoid alert flooding
        last_alert = self._alerted.get(key, 0)
        if now - last_alert < self.window:
            return None

        self._alerted[key] = now

        # Severity based on count
        if attempt_count >= self.threshold * 2:
            severity = "high"
        else:
            severity = "medium"

        service = _PORT_NAMES.get(dst_port, f"port {dst_port}")

        logger.warning(
            "Brute-force detected: %s → %s (%s): %d attempts in %ds",
            src_ip, service, dst_port, attempt_count, self.window,
        )

        return AlertEvent(
            source_ip=src_ip,
            dest_ip=packet_data.get("dest_ip"),
            dest_port=dst_port,
            protocol="TCP",
            alert_type="brute_force",
            severity=severity,
            description=(
                f"Brute-force attack on {service} (port {dst_port}): "
                f"{attempt_count} connection attempts in {self.window}s "
                f"(threshold: {self.threshold})"
            ),
            raw_packet=packet_data.get("raw_summary", ""),
        )

    def reset(self):
        """Clear all tracking state."""
        self._windows.clear()
        self._alerted.clear()
