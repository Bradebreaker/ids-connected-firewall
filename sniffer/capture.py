"""
sniffer/capture.py — Packet capture engine using Scapy.

Runs `scapy.sniff()` in a dedicated thread (via asyncio.to_thread) so
it never blocks the FastAPI event loop.  Each captured packet is parsed
into a lightweight dict and pushed onto an asyncio.Queue that the
detection pipeline consumes.

Requires root / CAP_NET_RAW privileges.
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Any

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
from config import settings

logger = logging.getLogger("ids.sniffer")


def _parse_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Extract relevant fields from a Scapy packet into a plain dict.

    Returns None for packets we can't meaningfully analyse (e.g. ARP).
    """
    data: Dict[str, Any] = {
        "timestamp": time.time(),
        "source_ip": None,
        "dest_ip": None,
        "source_port": None,
        "dest_port": None,
        "protocol": None,
        "tcp_flags": None,
        "payload": "",
        "packet_size": len(packet),
        "raw_summary": packet.summary(),
    }

    # ── IP layer ──────────────────────────────────────────────────
    if IP in packet:
        data["source_ip"] = packet[IP].src
        data["dest_ip"]   = packet[IP].dst
    elif IPv6 in packet:
        data["source_ip"] = packet[IPv6].src
        data["dest_ip"]   = packet[IPv6].dst
    else:
        return None  # Skip non-IP traffic (ARP, etc.)

    # ── Transport layer ──────────────────────────────────────────
    if TCP in packet:
        data["protocol"]    = "TCP"
        data["source_port"] = packet[TCP].sport
        data["dest_port"]   = packet[TCP].dport
        # Decode TCP flag bits into human-readable string
        data["tcp_flags"]   = str(packet[TCP].flags)
    elif UDP in packet:
        data["protocol"]    = "UDP"
        data["source_port"] = packet[UDP].sport
        data["dest_port"]   = packet[UDP].dport
    elif ICMP in packet:
        data["protocol"] = "ICMP"

    # ── Payload (first 500 bytes for signature matching) ─────────
    if Raw in packet:
        try:
            data["payload"] = bytes(packet[Raw].load[:500]).decode("utf-8", errors="replace")
        except Exception:
            data["payload"] = ""

    return data


def _sniff_blocking(packet_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    """
    Synchronous sniffing function that runs inside a thread.

    Scapy's sniff() is blocking, so we run it in its own thread.
    Each parsed packet is scheduled onto the async queue via the event loop.
    """
    def _process(packet):
        parsed = _parse_packet(packet)
        if parsed:
            # Thread-safe way to put onto the asyncio queue
            asyncio.run_coroutine_threadsafe(packet_queue.put(parsed), loop)

    logger.info(
        "Sniffer starting — interface=%s  filter='%s'",
        settings.SNIFFER_INTERFACE or "all",
        settings.SNIFFER_BPF_FILTER,
    )

    sniff_kwargs = {
        "prn": _process,
        "store": False,            # don't accumulate in memory
        "filter": settings.SNIFFER_BPF_FILTER,
    }
    if settings.SNIFFER_INTERFACE:
        sniff_kwargs["iface"] = settings.SNIFFER_INTERFACE

    sniff(**sniff_kwargs)          # blocks forever


async def start_sniffer(packet_queue: asyncio.Queue):
    """
    Launch the Scapy sniffer as a background task.

    Runs the blocking sniff in a thread so the FastAPI event loop
    stays responsive.
    """
    loop = asyncio.get_running_loop()
    logger.info("Launching packet sniffer background thread …")
    await asyncio.to_thread(_sniff_blocking, packet_queue, loop)
