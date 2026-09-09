"""
detection/syn_flood.py — SYN flood / traffic anomaly detection.

Tracks SYN packet rates per source IP using a rolling statistics model.
If the current rate exceeds the rolling mean + N standard deviations,
an alert fires.

This catches volumetric DoS attacks and abnormal traffic spikes.
"""

import logging
import math
import time
from collections import defaultdict, deque
from typing import Optional

from detection.base import BaseDetector
from db.schemas import AlertEvent
from config import settings

logger = logging.getLogger("ids.detection.syn_flood")


class _IPStats:
    """
    Rolling statistics tracker for a single source IP.

    Maintains a deque of SYN packet timestamps and computes
    mean/stddev of packets-per-window over successive windows.
    """

    def __init__(self, window: int):
        self.window = window
        self.timestamps: deque = deque()       # raw SYN timestamps
        self.rate_history: deque = deque(maxlen=20)  # last 20 window rates
        self.last_window_end: float = 0.0

    def add(self, ts: float):
        """Record a SYN packet timestamp."""
        self.timestamps.append(ts)

    def evict(self, now: float):
        """Remove timestamps outside the current window."""
        cutoff = now - self.window
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()

    @property
    def current_count(self) -> int:
        """Number of SYN packets in the current window."""
        return len(self.timestamps)

    def record_rate(self, rate: float):
        """Push a rate observation into the rolling history."""
        self.rate_history.append(rate)

    @property
    def mean(self) -> float:
        if not self.rate_history:
            return 0.0
        return sum(self.rate_history) / len(self.rate_history)

    @property
    def stddev(self) -> float:
        if len(self.rate_history) < 2:
            return 0.0
        m = self.mean
        variance = sum((r - m) ** 2 for r in self.rate_history) / len(self.rate_history)
        return math.sqrt(variance)


class SynFloodDetector(BaseDetector):
    """
    Detects SYN flood / volumetric anomalies using statistical deviation.

    Algorithm:
        1. Track all SYN packets per source IP in a sliding window.
        2. Every window period, compute the current rate and compare to
           the rolling mean + (N × stddev) of historical rates.
        3. If the current rate exceeds the dynamic threshold, fire an alert.

    The detector needs a minimum baseline of MIN_PACKETS observations
    before it starts alerting, to avoid false positives on low traffic.

    Severity scaling:
        - rate > mean + N*stddev      → medium
        - rate > mean + 2*N*stddev    → high
    """

    name = "SynFloodDetector"

    def __init__(self):
        self._ip_stats: dict = defaultdict(lambda: _IPStats(settings.SYN_FLOOD_WINDOW))
        self._alerted: dict = {}  # {source_ip: last_alert_ts}
        self.stddev_mult  = settings.SYN_FLOOD_STDDEV_MULTIPLIER
        self.window       = settings.SYN_FLOOD_WINDOW
        self.min_packets  = settings.SYN_FLOOD_MIN_PACKETS
        logger.info(
            "SynFloodDetector initialised: window=%ds, stddev_mult=%.1f, min_packets=%d",
            self.window, self.stddev_mult, self.min_packets,
        )

    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        """Check for SYN flood anomaly from this packet's source."""
        src_ip   = packet_data.get("source_ip")
        protocol = packet_data.get("protocol", "")
        flags    = packet_data.get("tcp_flags", "")

        if not src_ip or protocol != "TCP":
            return None

        # Only count SYN packets (not SYN-ACK, not pure ACK)
        flag_str = str(flags)
        if "S" not in flag_str or "A" in flag_str:
            return None

        now = packet_data.get("timestamp", time.time())
        stats = self._ip_stats[src_ip]
        stats.add(now)
        stats.evict(now)

        current_count = stats.current_count

        # Need enough baseline before alerting
        if sum(stats.rate_history) == 0 and current_count < self.min_packets:
            return None

        # Check if a full window has elapsed → record rate snapshot
        if now - stats.last_window_end >= self.window:
            stats.record_rate(current_count)
            stats.last_window_end = now

        # Need at least a few rate observations for meaningful statistics
        if len(stats.rate_history) < 3:
            return None

        mean   = stats.mean
        stddev = stats.stddev

        # Avoid division by zero or alerting on very low traffic
        if stddev < 1.0:
            return None

        threshold_medium = mean + self.stddev_mult * stddev
        threshold_high   = mean + 2 * self.stddev_mult * stddev

        if current_count < threshold_medium:
            return None

        # Rate limit alerts per IP
        last_alert = self._alerted.get(src_ip, 0)
        if now - last_alert < self.window:
            return None

        self._alerted[src_ip] = now

        if current_count >= threshold_high:
            severity = "high"
        else:
            severity = "medium"

        deviation = (current_count - mean) / stddev if stddev > 0 else 0

        logger.warning(
            "SYN flood detected from %s: %d SYN/window (mean=%.1f, stddev=%.1f, "
            "%.1f σ above mean)",
            src_ip, current_count, mean, stddev, deviation,
        )

        return AlertEvent(
            source_ip=src_ip,
            dest_ip=packet_data.get("dest_ip"),
            dest_port=packet_data.get("dest_port"),
            protocol="TCP",
            alert_type="syn_flood",
            severity=severity,
            description=(
                f"SYN flood anomaly: {current_count} SYN packets in {self.window}s "
                f"(baseline mean={mean:.1f}, stddev={stddev:.1f}, "
                f"{deviation:.1f}σ above normal)"
            ),
            raw_packet=packet_data.get("raw_summary", ""),
        )

    def reset(self):
        """Clear all tracking state."""
        self._ip_stats.clear()
        self._alerted.clear()
