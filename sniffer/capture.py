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


from sniffer.packet_event import create_packet_event, format_hex_dump, next_packet_number
from scapy.all import Ether

def _parse_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Extract relevant fields from a Scapy packet into a normalized event dict.
    Returns None for packets we can't meaningfully analyse (e.g. ARP).
    """
    src_ip = None
    dst_ip = None
    ip_version = 4
    ip_hl = 20
    ip_ttl = 64

    # ── IP layer ──────────────────────────────────────────────────
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_version = packet[IP].version
        ip_hl = packet[IP].ihl * 4
        ip_ttl = packet[IP].ttl
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ip_version = 6
        ip_hl = 40
        ip_ttl = packet[IPv6].hlim
    else:
        return None  # Skip non-IP traffic (ARP, etc.)

    protocol = "OTHER"
    sport = None
    dport = None
    tcp_flags = ""
    tcp_seq = None
    tcp_ack = None
    tcp_window = 65535

    # ── Transport layer ──────────────────────────────────────────
    if TCP in packet:
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)
        tcp_seq = int(packet[TCP].seq)
        tcp_ack = int(packet[TCP].ack)
        tcp_window = int(packet[TCP].window)
    elif UDP in packet:
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"

    # ── Payload ──────────────────────────────────────────────────
    payload = ""
    raw_bytes = bytes(packet)
    if Raw in packet:
        try:
            payload = bytes(packet[Raw].load[:500]).decode("utf-8", errors="replace")
        except Exception:
            payload = ""

    # ── Ethernet ─────────────────────────────────────────────────
    eth_src = packet[Ether].src if Ether in packet else "00:00:00:00:00:00"
    eth_dst = packet[Ether].dst if Ether in packet else "00:00:00:00:00:00"

    hex_dump = format_hex_dump(raw_bytes[:128])

    return create_packet_event(
        source_ip=src_ip,
        dest_ip=dst_ip or "192.168.1.1",
        source_port=sport,
        dest_port=dport,
        protocol=protocol,
        tcp_flags=tcp_flags,
        payload=payload,
        packet_size=len(packet),
        raw_summary=packet.summary(),
        eth_src=eth_src,
        eth_dst=eth_dst,
        ip_version=ip_version,
        ip_hl=ip_hl,
        ip_ttl=ip_ttl,
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        tcp_window=tcp_window,
        hex_dump=hex_dump,
    )


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
