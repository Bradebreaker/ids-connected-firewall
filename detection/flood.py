"""
detection/flood.py — Behavioral and rate-based flood detection.

Monitors volumetric protocol anomalies:
1. UDP Flood: High packet rate of UDP traffic from a single source.
2. ICMP Flood: Volumetric ICMP ping/echo flood from a single source.
3. Slowloris: Slow HTTP header starvation attack holding connections open.
"""

import time
import logging
from collections import defaultdict, deque
from typing import Optional

from detection.base import BaseDetector
from db.schemas import AlertEvent

logger = logging.getLogger("ids.detection.flood")


class FloodDetector(BaseDetector):
    """
    Detects UDP floods, ICMP floods, and Slowloris connection starvation attacks
    using sliding time windows.
    """

    name = "FloodDetector"

    def __init__(
        self,
        udp_threshold: int = 15,
        udp_window: float = 10.0,
        icmp_threshold: int = 15,
        icmp_window: float = 10.0,
        slowloris_threshold: int = 8,
        slowloris_window: float = 30.0,
    ):
        self.udp_threshold = udp_threshold
        self.udp_window = udp_window
        self.icmp_threshold = icmp_threshold
        self.icmp_window = icmp_window
        self.slowloris_threshold = slowloris_threshold
        self.slowloris_window = slowloris_window

        # Sliding windows: {source_ip: deque of timestamps}
        self._udp_windows: dict = defaultdict(deque)
        self._icmp_windows: dict = defaultdict(deque)
        self._slowloris_windows: dict = defaultdict(deque)

        # Alert cooldown tracking: {(source_ip, attack_type): last_alert_time}
        self._alerted: dict = {}

        logger.info(
            "FloodDetector initialized — UDP threshold=%d/%0.1fs, ICMP threshold=%d/%0.1fs, Slowloris threshold=%d/%0.1fs",
            self.udp_threshold, self.udp_window,
            self.icmp_threshold, self.icmp_window,
            self.slowloris_threshold, self.slowloris_window,
        )

    def _evict(self, dq: deque, cutoff: float):
        while dq and dq[0] < cutoff:
            dq.popleft()

    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        src_ip = packet_data.get("source_ip")
        if not src_ip:
            return None

        proto = packet_data.get("protocol", "").upper()
        now = packet_data.get("timestamp") or time.time()
        payload = packet_data.get("payload", "")

        # ── 1. UDP Flood Detection ──────────────────────────────────
        if proto == "UDP":
            dq = self._udp_windows[src_ip]
            dq.append(now)
            self._evict(dq, now - self.udp_window)

            if len(dq) >= self.udp_threshold:
                last_alert = self._alerted.get((src_ip, "udp_flood"), 0)
                if now - last_alert >= self.udp_window:
                    self._alerted[(src_ip, "udp_flood")] = now
                    logger.warning("UDP Flood detected from %s (%d packets in %0.1fs)", src_ip, len(dq), self.udp_window)
                    return AlertEvent(
                        source_ip=src_ip,
                        dest_ip=packet_data.get("dest_ip"),
                        dest_port=packet_data.get("dest_port"),
                        protocol="UDP",
                        alert_type="udp_flood",
                        severity="high",
                        description=f"UDP Flood detected: {len(dq)} UDP packets from {src_ip} in {self.udp_window}s window (threshold: {self.udp_threshold})",
                        raw_packet=packet_data.get("raw_summary", ""),
                    )

        # ── 2. ICMP Flood Detection ─────────────────────────────────
        elif proto == "ICMP":
            dq = self._icmp_windows[src_ip]
            dq.append(now)
            self._evict(dq, now - self.icmp_window)

            if len(dq) >= self.icmp_threshold:
                last_alert = self._alerted.get((src_ip, "icmp_flood"), 0)
                if now - last_alert >= self.icmp_window:
                    self._alerted[(src_ip, "icmp_flood")] = now
                    logger.warning("ICMP Flood detected from %s (%d packets in %0.1fs)", src_ip, len(dq), self.icmp_window)
                    return AlertEvent(
                        source_ip=src_ip,
                        dest_ip=packet_data.get("dest_ip"),
                        dest_port=None,
                        protocol="ICMP",
                        alert_type="icmp_flood",
                        severity="high",
                        description=f"ICMP Echo Flood detected: {len(dq)} ICMP packets from {src_ip} in {self.icmp_window}s window (threshold: {self.icmp_threshold})",
                        raw_packet=packet_data.get("raw_summary", ""),
                    )

        # ── 3. Slowloris (Slow HTTP Denial of Service) ───────────────
        if proto == "TCP" and packet_data.get("dest_port") in [80, 443, 8080, 8000]:
            # Slowloris sends keep-alive headers like "X-a: b\r\n" or incomplete headers periodically
            is_slowloris_pattern = (
                ("X-a:" in payload or "X-Slowloris:" in payload or "GET /" in payload)
                and not payload.endswith("\r\n\r\n")
            )
            if is_slowloris_pattern:
                dq = self._slowloris_windows[src_ip]
                dq.append(now)
                self._evict(dq, now - self.slowloris_window)

                if len(dq) >= self.slowloris_threshold:
                    last_alert = self._alerted.get((src_ip, "slowloris"), 0)
                    if now - last_alert >= self.slowloris_window:
                        self._alerted[(src_ip, "slowloris")] = now
                        logger.warning("Slowloris attack detected from %s (%d partial headers)", src_ip, len(dq))
                        return AlertEvent(
                            source_ip=src_ip,
                            dest_ip=packet_data.get("dest_ip"),
                            dest_port=packet_data.get("dest_port"),
                            protocol="TCP",
                            alert_type="slowloris",
                            severity="medium",
                            description=f"Slowloris DoS detected: {len(dq)} incomplete HTTP header fragments from {src_ip} in {self.slowloris_window}s (threshold: {self.slowloris_threshold})",
                            raw_packet=packet_data.get("raw_summary", ""),
                        )

        return None
