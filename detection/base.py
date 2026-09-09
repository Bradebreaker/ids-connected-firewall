"""
detection/base.py — Abstract base class for all IDS detectors.

Every detection technique (signature, port scan, brute force, SYN flood)
inherits from BaseDetector and implements `analyze()`.  This makes each
detector independently testable and hot-swappable.
"""

from abc import ABC, abstractmethod
from typing import Optional
from db.schemas import AlertEvent


class BaseDetector(ABC):
    """
    Abstract base for intrusion detection modules.

    Subclasses must implement `analyze(packet_data)` which inspects
    a parsed packet dict and returns an AlertEvent if a threat is
    detected, or None if the packet is benign.
    """

    # Human-readable name for logging
    name: str = "BaseDetector"

    @abstractmethod
    async def analyze(self, packet_data: dict) -> Optional[AlertEvent]:
        """
        Analyse a single parsed packet.

        Args:
            packet_data: dict with keys source_ip, dest_ip, dest_port,
                         protocol, tcp_flags, payload, packet_size, etc.

        Returns:
            AlertEvent if a threat is detected, else None.
        """
        ...

    def reset(self):
        """
        Reset internal state (e.g. sliding windows).
        Useful for testing.
        """
        pass
