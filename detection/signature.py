"""
detection/signature.py — Signature-based intrusion detection.

Scans packet payloads against high-fidelity regex patterns for known malicious content:
SQL injection, XSS, directory traversal, shell command injection, Log4Shell, SSRF,
HTTP Request Smuggling, API Abuse, Credential Stuffing, JWT/Auth Abuse, DNS Tunneling,
LDAP Injection, XXE, SSTI, and Insecure Deserialization.
"""

import re
import logging
from typing import Optional, List, Tuple
from detection.base import BaseDetector
from db.schemas import AlertEvent

logger = logging.getLogger("ids.detection.signature")


# ══════════════════════════════════════════════════════════════════════
#  Signature rule definitions
#  Each rule: (name, compiled_regex, severity, attack_type)
# ══════════════════════════════════════════════════════════════════════

_SIGNATURE_RULES: List[Tuple[str, re.Pattern, str, str]] = [
    # ── SQL Injection patterns ────────────────────────────────────
    (
        "SQL Injection — UNION SELECT",
        re.compile(r"(?i)(union\s+(all\s+)?select)", re.IGNORECASE),
        "high",
        "sql_injection",
    ),
    (
        "SQL Injection — OR 1=1",
        re.compile(r"(?i)(\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)", re.IGNORECASE),
        "high",
        "sql_injection",
    ),
    (
        "SQL Injection — DROP TABLE",
        re.compile(r"(?i)(drop\s+table)", re.IGNORECASE),
        "high",
        "sql_injection",
    ),
    (
        "SQL Injection — comment injection",
        re.compile(r"(--|#|/\*.*?\*/)", re.IGNORECASE),
        "low",
        "sql_injection",
    ),
    (
        "SQL Injection — SLEEP / BENCHMARK",
        re.compile(r"(?i)(sleep\s*\(\d+\)|benchmark\s*\()", re.IGNORECASE),
        "high",
        "sql_injection",
    ),

    # ── XSS (Cross-Site Scripting) ────────────────────────────────
    (
        "XSS — script tag",
        re.compile(r"(?i)(<\s*script[^>]*>)", re.IGNORECASE),
        "high",
        "xss",
    ),
    (
        "XSS — event handler",
        re.compile(r"(?i)(on(load|error|click|mouseover)\s*=)", re.IGNORECASE),
        "medium",
        "xss",
    ),
    (
        "XSS — javascript: URI",
        re.compile(r"(?i)(javascript\s*:)", re.IGNORECASE),
        "medium",
        "xss",
    ),
    (
        "XSS — img/svg injection",
        re.compile(r"(?i)(<\s*(img|svg|iframe)[^>]+>)", re.IGNORECASE),
        "medium",
        "xss",
    ),

    # ── Directory / Path Traversal ─────────────────────────────────
    (
        "Directory Traversal — dot-dot-slash",
        re.compile(r"(\.\./|\.\.\\){2,}", re.IGNORECASE),
        "high",
        "path_traversal",
    ),
    (
        "Path Traversal — /etc/passwd",
        re.compile(r"(?i)(/etc/(passwd|shadow|hosts))", re.IGNORECASE),
        "high",
        "path_traversal",
    ),
    (
        "Path Traversal — URL Encoded",
        re.compile(r"(?i)((%2e%2e%2f)+|(%2e%2e/)+|(\.\.%2f)+)", re.IGNORECASE),
        "high",
        "path_traversal",
    ),

    # ── Command Injection ─────────────────────────────────────────
    (
        "Command Injection — shell metachar",
        re.compile(r"(;\s*(ls|cat|whoami|id|uname|wget|curl)\b)", re.IGNORECASE),
        "high",
        "command_injection",
    ),
    (
        "Command Injection — backtick",
        re.compile(r"`[^`]+`", re.IGNORECASE),
        "medium",
        "command_injection",
    ),
    (
        "Command Injection — $() substitution",
        re.compile(r"\$\([^)]+\)", re.IGNORECASE),
        "medium",
        "command_injection",
    ),

    # ── Shellshock ────────────────────────────────────────────────
    (
        "Shellshock attempt",
        re.compile(r"\(\)\s*\{", re.IGNORECASE),
        "high",
        "shellshock",
    ),

    # ── Log4Shell ─────────────────────────────────────────────────
    (
        "Log4Shell (CVE-2021-44228)",
        re.compile(r"(?i)(\$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http):/[^\}]+})", re.IGNORECASE),
        "high",
        "log4shell",
    ),

    # ── SSRF ──────────────────────────────────────────────────────
    (
        "SSRF — Cloud Metadata Request",
        re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal)", re.IGNORECASE),
        "high",
        "cloud_ssrf",
    ),

    # ── PHP / RCE ─────────────────────────────────────────────────
    (
        "RCE — PHP/Command Injection",
        re.compile(r"(?i)(<\?php|phpinfo\(\)|system\(|exec\(|eval\()", re.IGNORECASE),
        "high",
        "php_rce",
    ),

    # ── Modern Attacks ────────────────────────────────────────────
    # 1. HTTP Request Smuggling
    (
        "HTTP Request Smuggling — Dual TE/CL or Obfuscated Header",
        re.compile(r"(?i)(Transfer-Encoding:\s*chunked[\s\S]*Content-Length:|Content-Length:[\s\S]*Transfer-Encoding:\s*chunked|Transfer-Encoding:.*[\r\n]+Transfer-Encoding:)", re.IGNORECASE),
        "high",
        "http_request_smuggling",
    ),

    # 2. API Abuse / Broken Object Level Authorization & GraphQL Introspection
    (
        "API Abuse — Unauthorized Admin Endpoint / Schema Dump",
        re.compile(r"(?i)(/(api/)?v\d+/(admin|internal|system)/users/export|__schema\s*\{|__type\(name:)", re.IGNORECASE),
        "medium",
        "api_abuse",
    ),

    # 3. Credential Stuffing
    (
        "Credential Stuffing — Common Wordlist Payload Spray",
        re.compile(r"(?i)(password=(admin|123456|password|qwerty|root|toor|letmein123|welcome1)\b|auth/login.*combo_list)", re.IGNORECASE),
        "high",
        "credential_stuffing",
    ),

    # 4. JWT / Auth Abuse
    (
        "JWT / Auth Abuse — alg:none / Malformed Signature",
        re.compile(r"(?i)(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.(none)?\b|\"alg\"\s*:\s*\"none\")", re.IGNORECASE),
        "high",
        "jwt_attack",
    ),

    # 5. DNS Tunneling
    (
        "DNS Tunneling — High-Entropy Hex/Base32 Query Exfiltration",
        re.compile(r"(?i)([a-f0-9]{24,}\.(tunnel|exfil|data|dns)\.)", re.IGNORECASE),
        "high",
        "dns_tunneling",
    ),

    # 6. LDAP Injection
    (
        "LDAP Injection — Wildcard / Boolean Filter Manipulation",
        re.compile(r"(?i)(\(&\(|\(\|\(|[a-z0-9_]+\s*=\s*\*|\*\s*\)\s*\([a-z0-9_]+\s*=)", re.IGNORECASE),
        "high",
        "ldap_injection",
    ),

    # 7. XML External Entity (XXE)
    (
        "XXE — External Entity System Declaration",
        re.compile(r"(?i)(<!ENTITY\s+[a-z0-9_-]+\s+SYSTEM\s+[\'\"](file|http|ftp|php):)", re.IGNORECASE),
        "high",
        "xxe",
    ),

    # 8. Server-Side Template Injection (SSTI)
    (
        "SSTI — Template Expression Execution",
        re.compile(r"(?i)(\{\{.*(config|self|__class__|mro|subclasses|request|app|lipsum|cycler).*\}\}|\$\{7\*7\}|\{\{7\*7\}\})", re.IGNORECASE),
        "high",
        "ssti",
    ),

    # 9. Insecure Deserialization
    (
        "Insecure Deserialization — Serialized Object Header",
        re.compile(r"(rO0AB[A-Za-z0-9+/]|cos\nsystem|O:\d+:\"[^\"]+\":\d+:\{)", re.IGNORECASE),
        "high",
        "insecure_deserialization",
    ),

    # ── Recon Scanner User Agents ─────────────────────────────────
    (
        "Suspicious User-Agent — Security Scanner",
        re.compile(r"(?i)(nmap|nikto|sqlmap|masscan|dirbuster|gobuster|wpscan)", re.IGNORECASE),
        "medium",
        "api_abuse",
    ),
]


class SignatureDetector(BaseDetector):
    """
    Matches packet payloads against known-bad regex signatures.
    Classifies the specific attack type for direct linking to Attack Intelligence.
    """

    name = "SignatureDetector"

    def __init__(self):
        self.rules = _SIGNATURE_RULES
        logger.info("Loaded %d signature rules across all attack categories", len(self.rules))

    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        """Check the packet payload against all signature rules."""
        payload = packet_data.get("payload", "")
        if not payload or len(payload) < 3:
            return None  # No meaningful payload to inspect

        for rule_name, pattern, severity, attack_type in self.rules:
            match = pattern.search(payload)
            if match:
                matched_snippet = match.group()[:80]
                logger.warning(
                    "Signature match: '%s' [%s] from %s (matched: %s)",
                    rule_name,
                    attack_type,
                    packet_data.get("source_ip"),
                    matched_snippet,
                )
                return AlertEvent(
                    source_ip=packet_data["source_ip"],
                    dest_ip=packet_data.get("dest_ip"),
                    dest_port=packet_data.get("dest_port"),
                    protocol=packet_data.get("protocol"),
                    alert_type=attack_type,
                    severity=severity,
                    description=f"Signature match: {rule_name} — matched '{matched_snippet}'",
                    raw_packet=packet_data.get("raw_summary", ""),
                )

        return None
