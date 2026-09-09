"""
detection/port_scan.py — Port scan detection using sliding time windows.

Tracks the number of distinct destination ports touched by each source IP
within a configurable time window.  If a source exceeds the threshold,
an alert is raised.

Uses collections.deque keyed by source IP for efficient window management.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Optional

from detection.base import BaseDetector
from db.schemas import AlertEvent
from config import settings

logger = logging.getLogger("ids.detection.port_scan")


class PortScanDetector(BaseDetector):
    """
    Detects port scanning by tracking distinct destination ports per source IP.

    Algorithm:
        1. For each packet, record (timestamp, dest_port) in a deque keyed by source IP.
        2. Evict entries older than the sliding window.
        3. Count distinct dest_ports in the window.
        4. If count >= threshold, fire an alert.

    Severity scaling:
        - threshold .. 2×threshold  → medium
        - > 2×threshold             → high
    """

    name = "PortScanDetector"

    def __init__(self):
        # {source_ip: deque of (timestamp, dest_port)}
        self._windows: dict = defaultdict(deque)
        # Track which IPs we've already alerted on (to avoid alert flooding)
        self._alerted: dict = {}  # {source_ip: last_alert_timestamp}
        self.threshold = settings.PORT_SCAN_THRESHOLD
        self.window    = settings.PORT_SCAN_WINDOW
        logger.info(
            "PortScanDetector initialised: threshold=%d ports in %ds window",
            self.threshold, self.window,
        )

    def _evict_old(self, ip: str, now: float):
        """Remove entries outside the sliding window."""
        dq = self._windows[ip]
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        """Track dest ports per source IP and detect scans."""
        src_ip   = packet_data.get("source_ip")
        dst_port = packet_data.get("dest_port")

        # Need both source IP and destination port for port scan detection
        if not src_ip or dst_port is None:
            return None

        now = packet_data.get("timestamp", time.time())

        # Record this connection attempt
        self._windows[src_ip].append((now, dst_port))
        self._evict_old(src_ip, now)

        # Count distinct destination ports in the window
        distinct_ports = set(port for _, port in self._windows[src_ip])
        port_count = len(distinct_ports)

        if port_count < self.threshold:
            return None

        # Avoid flooding: only alert once per window per IP
        last_alert = self._alerted.get(src_ip, 0)
        if now - last_alert < self.window:
            return None

        self._alerted[src_ip] = now

        # Determine severity based on how far over the threshold
        if port_count >= self.threshold * 2:
            severity = "high"
        else:
            severity = "medium"

        logger.warning(
            "Port scan detected from %s: %d distinct ports in %ds",
            src_ip, port_count, self.window,
        )

        return AlertEvent(
            source_ip=src_ip,
            dest_ip=packet_data.get("dest_ip"),
            dest_port=dst_port,
            protocol=packet_data.get("protocol"),
            alert_type="port_scan",
            severity=severity,
            description=(
                f"Port scan detected: {port_count} distinct destination ports "
                f"scanned in {self.window}s window (threshold: {self.threshold})"
            ),
            raw_packet=packet_data.get("raw_summary", ""),
        )

    def reset(self):
        """Clear all tracking state (for testing)."""
        self._windows.clear()
        self._alerted.clear()
