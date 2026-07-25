"""
models.py
---------
Defines the data structures used to represent a captured network packet.

These models act as the contract between the Packet Capture Engine and
downstream consumers (e.g. the AI inference / explainability modules of the
Adaptive Firewall). Keeping this in its own file follows clean architecture:
the "entities" layer has no dependency on Scapy, sockets, or I/O of any kind.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProtocolType(str, Enum):
    """
    Enumerates the transport/network-layer protocols this engine understands.

    Using a string Enum (rather than raw strings scattered through the code)
    prevents typos like "TCP " vs "tcp" from silently breaking downstream
    filtering or AI feature extraction.
    """
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


@dataclass
class PacketData:
    """
    Immutable-style container representing a single parsed network packet.

    This is the object returned by the capture engine for every valid packet
    it observes. Every field is deliberately simple (str/int/float) so that
    the object can be trivially serialized to JSON, fed into a pandas
    DataFrame, or converted into a feature vector for an ML model without
    any custom encoding logic.

    Attributes:
        src_ip: Source IPv4/IPv6 address.
        dst_ip: Destination IPv4/IPv6 address.
        src_port: Source port number (None for protocols without ports, e.g. ICMP).
        dst_port: Destination port number (None for protocols without ports, e.g. ICMP).
        protocol: The transport protocol, as a ProtocolType.
        length: Total length of the captured packet, in bytes.
        timestamp: Unix epoch timestamp (seconds, float) of when the packet was captured.
    """
    src_ip: str
    dst_ip: str
    protocol: ProtocolType
    length: int
    timestamp: float
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Extra metadata slot for future AI features (e.g. TCP flags, TTL) without
    # having to break the constructor signature used elsewhere in the system.
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Convert this packet record into a plain dictionary.

        This is the primary hand-off format to the AI/explainability layer,
        since dictionaries are easy to serialize (JSON), log, or convert into
        a pandas DataFrame row for feature engineering.
        """
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "length": self.length,
            "timestamp": self.timestamp,
            "extra": self.extra,
        }

    def __str__(self) -> str:
        """Human-readable summary, useful for logging/debugging."""
        return (
            f"[{self.protocol.value}] {self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} len={self.length} ts={self.timestamp}"
        )
