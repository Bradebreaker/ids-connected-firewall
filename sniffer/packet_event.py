"""
sniffer/packet_event.py — Common Normalized Packet Event Model.

Provides a unified packet event structure for both real Scapy-captured packets
and synthetically injected packets. Ensures all downstream systems (detectors,
WebSocket broadcasts, Wireshark-like Live Traffic Analyzer) receive consistent,
rich inspection fields.
"""

import time
import random
import threading
from collections import deque
from typing import Dict, Any, Optional, List

_global_packet_counter = 0
_counter_lock = threading.Lock()

# Bounded in-memory recent packet buffer (max 1000 packets)
_recent_packets_buffer = deque(maxlen=1000)
_buffer_lock = threading.Lock()


def next_packet_number() -> int:
    """Increment and return the next sequential packet number."""
    global _global_packet_counter
    with _counter_lock:
        _global_packet_counter += 1
        return _global_packet_counter


def get_current_packet_count() -> int:
    """Return total lifetime number of packets processed so far."""
    with _counter_lock:
        return _global_packet_counter


def record_packet(pkt: Dict[str, Any]) -> None:
    """Thread-safe append of a packet to the recent rolling buffer."""
    with _buffer_lock:
        _recent_packets_buffer.append(pkt)


def get_recent_packets(limit: int = 200) -> List[Dict[str, Any]]:
    """Return a snapshot of the most recent packets (newest last)."""
    with _buffer_lock:
        items = list(_recent_packets_buffer)
    if limit and len(items) > limit:
        return items[-limit:]
    return items


def get_recent_buffer_count() -> int:
    """Return current number of packets in the rolling buffer."""
    with _buffer_lock:
        return len(_recent_packets_buffer)


def reset_recent_packets() -> None:
    """Clear the in-memory recent packet buffer for demonstration reset without touching database."""
    with _buffer_lock:
        _recent_packets_buffer.clear()


def format_hex_dump(payload_bytes: bytes, max_bytes: int = 128) -> str:
    """
    Format bytes into a Wireshark-style hexadecimal and ASCII dump.
    Example:
    0000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 0f  |E..<.@.@........|
    """
    if not payload_bytes:
        return "0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|"

    data = payload_bytes[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part1 = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_part2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{hex_part1:<23}  {hex_part2:<23}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_str}  |{ascii_str}|")

    return "\n".join(lines)


def generate_synthetic_hex(proto: str, payload_str: str) -> str:
    """Generate a realistic hex dump based on protocol and payload."""
    header_bytes = bytes([
        0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x06 if proto == "TCP" else (0x11 if proto == "UDP" else 0x01),
        0x7a, 0xbc, 0xc0, 0xa8, 0x01, 0x0a, 0xc0, 0xa8, 0x01, 0x01
    ])
    if payload_str:
        payload_bytes = payload_str.encode("utf-8", errors="replace")
    else:
        payload_bytes = bytes([random.randint(0, 255) for _ in range(16)])
    return format_hex_dump(header_bytes + payload_bytes)


def create_packet_event(
    source_ip: str,
    dest_ip: str = "192.168.1.10",
    source_port: Optional[int] = None,
    dest_port: Optional[int] = None,
    protocol: str = "TCP",
    tcp_flags: str = "S",
    payload: str = "",
    packet_size: Optional[int] = None,
    raw_summary: Optional[str] = None,
    timestamp: Optional[float] = None,
    threat_level: str = "NORMAL",
    threat_type: Optional[str] = None,
    threat_detail: Optional[str] = None,
    info: Optional[str] = None,
    eth_src: Optional[str] = None,
    eth_dst: Optional[str] = None,
    eth_type: str = "IPv4 (0x0800)",
    ip_version: int = 4,
    ip_hl: int = 20,
    ip_ttl: int = 64,
    tcp_seq: Optional[int] = None,
    tcp_ack: Optional[int] = None,
    tcp_window: int = 65535,
    hex_dump: Optional[str] = None,
    alert_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a standardized, normalized packet event object adhering to the unified schema.
    Provides complete 7-layer inspection fields at both top-level and nested structure.
    """
    pkt_num = next_packet_number()
    ts = timestamp if timestamp is not None else time.time()
    sport = source_port if source_port is not None else random.randint(1024, 65535)
    size = packet_size if packet_size is not None else (len(payload) + 54 if payload else random.randint(54, 1500))

    if not eth_src:
        eth_src = f"52:54:00:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}"
    if not eth_dst:
        eth_dst = "00:0c:29:4f:8e:35"

    is_tcp = (protocol == "TCP")
    seq = tcp_seq if tcp_seq is not None else (random.randint(100000, 99999999) if is_tcp else None)
    ack = tcp_ack if tcp_ack is not None else ((random.randint(100000, 99999999) if "A" in tcp_flags else 0) if is_tcp else None)
    flags_val = tcp_flags if is_tcp else "N/A"
    win_val = tcp_window if is_tcp else None

    # Determine summary info if not provided
    if not info:
        if protocol == "TCP":
            if tcp_flags == "S":
                info = f"{sport} → {dest_port} [SYN] Seq={seq} Win={tcp_window} Len=0"
            elif "PA" in tcp_flags or "P" in tcp_flags:
                info = f"{sport} → {dest_port} [PSH, ACK] Seq={seq} Ack={ack} Len={len(payload)}"
            elif "FA" in tcp_flags or "F" in tcp_flags:
                info = f"{sport} → {dest_port} [FIN, ACK] Seq={seq} Ack={ack}"
            elif "RA" in tcp_flags or "R" in tcp_flags:
                info = f"{sport} → {dest_port} [RST, ACK]"
            else:
                info = f"{sport} → {dest_port} [{tcp_flags}] Seq={seq} Ack={ack}"
        elif protocol == "UDP":
            if dest_port == 53 or sport == 53:
                info = f"Standard query 0x{random.randint(0x1000, 0xffff):04x} A {payload[:20] if payload else 'example.com'}"
            else:
                info = f"UDP Source Port: {sport} Destination Port: {dest_port} Len={size}"
        elif protocol == "ICMP":
            info = f"Echo (ping) request id=0x{random.randint(1, 255):04x}, seq={pkt_num}, ttl={ip_ttl}"
        else:
            info = f"{protocol} packet from {source_ip} to {dest_ip}"

    if not raw_summary:
        raw_summary = f"{protocol} {source_ip}:{sport} > {dest_ip}:{dest_port} [{flags_val}] {info}"

    if not hex_dump:
        hex_dump = generate_synthetic_hex(protocol, payload)

    return {
        # Core identification & timestamp
        "packet_number": pkt_num,
        "timestamp": ts,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "dest_ip": dest_ip,  # backward compatibility
        "source_port": sport,
        "destination_port": dest_port,
        "dest_port": dest_port,  # backward compatibility
        "protocol": protocol,
        "packet_length": size,
        "packet_size": size,  # backward compatibility
        "tcp_flags": flags_val,
        "payload": payload,
        "raw_summary": raw_summary,
        "info": info,

        # Ethernet frame fields (both top-level & nested)
        "eth_src": eth_src,
        "eth_dst": eth_dst,
        "eth_type": eth_type,
        "ethernet": {
            "src": eth_src,
            "dst": eth_dst,
            "type": eth_type,
        },

        # IPv4/IPv6 layer fields (both top-level & nested)
        "ip_version": ip_version,
        "ip_header_length": ip_hl,
        "ip_ttl": ip_ttl,
        "ip": {
            "version": ip_version,
            "ihl": ip_hl,
            "ttl": ip_ttl,
            "src": source_ip,
            "dst": dest_ip,
            "proto": protocol,
        },

        # Transport layer fields (both top-level & nested)
        "tcp_seq": seq,
        "tcp_ack": ack,
        "tcp_window": win_val,
        "transport": {
            "sport": sport,
            "dport": dest_port,
            "seq": seq if seq is not None else 0,
            "ack": ack if ack is not None else 0,
            "flags": flags_val,
            "window": win_val if win_val is not None else 0,
        },

        # Hexadecimal inspection
        "hex_dump": hex_dump,

        # Threat classification
        "threat_level": threat_level,  # NORMAL | SUSPICIOUS | MALICIOUS
        "threat_type": threat_type,
        "threat_detail": threat_detail,
        "alert_id": alert_id,
    }
