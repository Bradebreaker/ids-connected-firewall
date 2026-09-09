"""
detection/signature.py — Signature-based intrusion detection.

Scans packet payloads against a maintained list of regex patterns for
known malicious content: SQL injection, XSS, directory traversal,
shell command injection, etc.

Severity is determined by the risk category of the matched pattern.
"""

import re
import logging
from typing import Optional, List, Tuple
from detection.base import BaseDetector
from db.schemas import AlertEvent

logger = logging.getLogger("ids.detection.signature")


# ══════════════════════════════════════════════════════════════════════
#  Signature rule definitions
#  Each rule: (name, compiled_regex, severity)
# ══════════════════════════════════════════════════════════════════════

_SIGNATURE_RULES: List[Tuple[str, re.Pattern, str]] = [
    # ── SQL Injection patterns ────────────────────────────────────
    (
        "SQL Injection — UNION SELECT",
        re.compile(r"(?i)(union\s+(all\s+)?select)", re.IGNORECASE),
        "high",
    ),
    (
        "SQL Injection — OR 1=1",
        re.compile(r"(?i)(\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)", re.IGNORECASE),
        "high",
    ),
    (
        "SQL Injection — DROP TABLE",
        re.compile(r"(?i)(drop\s+table)", re.IGNORECASE),
        "high",
    ),
    (
        "SQL Injection — comment injection",
        re.compile(r"(--|#|/\*.*?\*/)", re.IGNORECASE),
        "low",
    ),
    (
        "SQL Injection — SLEEP / BENCHMARK",
        re.compile(r"(?i)(sleep\s*\(\d+\)|benchmark\s*\()", re.IGNORECASE),
        "high",
    ),

    # ── XSS (Cross-Site Scripting) ────────────────────────────────
    (
        "XSS — script tag",
        re.compile(r"(?i)(<\s*script[^>]*>)", re.IGNORECASE),
        "high",
    ),
    (
        "XSS — event handler",
        re.compile(r"(?i)(on(load|error|click|mouseover)\s*=)", re.IGNORECASE),
        "medium",
    ),
    (
        "XSS — javascript: URI",
        re.compile(r"(?i)(javascript\s*:)", re.IGNORECASE),
        "medium",
    ),
    (
        "XSS — img/svg injection",
        re.compile(r"(?i)(<\s*(img|svg|iframe)[^>]+>)", re.IGNORECASE),
        "medium",
    ),

    # ── Directory Traversal ───────────────────────────────────────
    (
        "Directory Traversal",
        re.compile(r"(\.\./|\.\.\\){2,}", re.IGNORECASE),
        "high",
    ),
    (
        "Path Traversal — /etc/passwd",
        re.compile(r"(?i)(/etc/(passwd|shadow|hosts))", re.IGNORECASE),
        "high",
    ),

    # ── Command Injection ─────────────────────────────────────────
    (
        "Command Injection — shell metachar",
        re.compile(r"(;\s*(ls|cat|whoami|id|uname|wget|curl)\b)", re.IGNORECASE),
        "high",
    ),
    (
        "Command Injection — backtick",
        re.compile(r"`[^`]+`", re.IGNORECASE),
        "medium",
    ),
    (
        "Command Injection — $() substitution",
        re.compile(r"\$\([^)]+\)", re.IGNORECASE),
        "medium",
    ),

    # ── Suspicious HTTP patterns ──────────────────────────────────
    (
        "Suspicious User-Agent — nmap/nikto/sqlmap",
        re.compile(r"(?i)(nmap|nikto|sqlmap|masscan|dirbuster)", re.IGNORECASE),
        "medium",
    ),
    (
        "Shellshock attempt",
        re.compile(r"\(\)\s*\{", re.IGNORECASE),
        "high",
    ),
]


class SignatureDetector(BaseDetector):
    """
    Matches packet payloads against known-bad regex signatures.

    This is the simplest detection technique: if the payload matches
    a known attack pattern, raise an alert with the corresponding severity.
    """

    name = "SignatureDetector"

    def __init__(self):
        self.rules = _SIGNATURE_RULES
        logger.info("Loaded %d signature rules", len(self.rules))

    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        """Check the packet payload against all signature rules."""
        payload = packet_data.get("payload", "")
        if not payload or len(payload) < 3:
            return None  # No meaningful payload to inspect

        for rule_name, pattern, severity in self.rules:
            match = pattern.search(payload)
            if match:
                logger.warning(
                    "Signature match: '%s' from %s (matched: %s)",
                    rule_name,
                    packet_data.get("source_ip"),
                    match.group()[:80],
                )
                return AlertEvent(
                    source_ip=packet_data["source_ip"],
                    dest_ip=packet_data.get("dest_ip"),
                    dest_port=packet_data.get("dest_port"),
                    protocol=packet_data.get("protocol"),
                    alert_type="signature",
                    severity=severity,
                    description=f"Signature match: {rule_name} — matched '{match.group()[:100]}'",
                    raw_packet=packet_data.get("raw_summary", ""),
                )

        return None
