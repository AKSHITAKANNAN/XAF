"""
models.py (Module 2)
---------------------
Data structures produced/consumed by the Feature Extraction Engine.

WHY THIS FILE EXISTS
Following the same "entities have no I/O dependencies" rule used in
Module 1: these are plain dataclasses/enums with no Scapy, socket, or
threading imports. This is the contract that Module 3 (AI Detection) will
consume, so it must stay stable, simple, and trivially serializable.

USED BY
- flow_builder.py       (builds/updates FlowKey identity + connection state)
- session_manager.py    (stores flows keyed by FlowKey)
- feature_extractor.py  (assembles the final FeatureVector)
- Module 3 (future)     (consumes FeatureVector as AI model input)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PacketDirection(str, Enum):
    """
    Classifies a packet's direction relative to the configured "home"
    network (see config.py -> home_networks).
    """
    INBOUND = "INBOUND"     # Traffic entering the home network from outside.
    OUTBOUND = "OUTBOUND"   # Traffic leaving the home network.
    INTERNAL = "INTERNAL"   # Both endpoints are inside the home network.
    UNKNOWN = "UNKNOWN"     # Direction could not be determined.


class ConnectionState(str, Enum):
    """
    Simplified connection state, primarily derived from TCP flags.

    For stateless protocols (UDP/ICMP) we use STATELESS instead of forcing
    a TCP-style state machine onto them.
    """
    NEW = "NEW"                 # First packet observed for this flow (e.g. TCP SYN).
    ESTABLISHED = "ESTABLISHED"  # Data flowing normally / handshake completed.
    CLOSING = "CLOSING"          # FIN observed, connection winding down.
    CLOSED = "CLOSED"            # RST observed, or FIN handshake completed.
    STATELESS = "STATELESS"      # Protocol has no connection concept (UDP/ICMP).
    UNKNOWN = "UNKNOWN"          # Not enough information to classify.


@dataclass(frozen=True)
class FlowKey:
    """
    Canonical, direction-independent identity of a network flow.

    A "flow" is the set of all packets belonging to the same conversation
    between two endpoints, regardless of which side sent a given packet.
    To make this direction-independent, the two (ip, port) endpoints are
    stored in a fixed, sorted order (endpoint_1 <= endpoint_2) so that a
    request and its reply hash to the *same* FlowKey.

    Attributes:
        endpoint_1_ip / endpoint_1_port: The "lower" endpoint (sorted).
        endpoint_2_ip / endpoint_2_port: The "higher" endpoint (sorted).
        protocol: Transport protocol string (e.g. "TCP", "UDP", "ICMP").
    """
    endpoint_1_ip: str
    endpoint_1_port: int
    endpoint_2_ip: str
    endpoint_2_port: int
    protocol: str

    def __str__(self) -> str:
        return (
            f"{self.protocol}:{self.endpoint_1_ip}:{self.endpoint_1_port}"
            f"<->{self.endpoint_2_ip}:{self.endpoint_2_port}"
        )


@dataclass
class FeatureVector:
    """
    AI-ready representation of a single packet, enriched with flow-level
    context. This is the sole output type of the Feature Extraction Engine.

    Field groups mirror the specification exactly:
      - Basic Features: copied directly from Module 1's PacketData.
      - Advanced Features: per-packet metadata + flow-state context.
      - Statistics: rate/average measures computed over the packet's flow.
    """

    # ---- Basic Features -------------------------------------------------
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_length: int
    timestamp: float

    # ---- Advanced Features ----------------------------------------------
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    window_size: Optional[int] = None
    direction: PacketDirection = PacketDirection.UNKNOWN
    flow_id: str = ""
    flow_duration: float = 0.0
    connection_state: ConnectionState = ConnectionState.UNKNOWN
    total_packets_in_flow: int = 0
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    payload_size: int = 0
    packet_arrival_time: float = 0.0
    inter_arrival_time: Optional[float] = None

    # ---- Statistics -------------------------------------------------------
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    avg_flow_time: float = 0.0

    # Free-form slot for anything Module 3 wants to attach without
    # breaking this dataclass's schema (mirrors Module 1's PacketData.extra).
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Serialize this FeatureVector into a plain dictionary.

        This is the hand-off format to Module 3 (AI Detection Engine),
        since dicts convert trivially into a pandas DataFrame row, a numpy
        feature array, or a JSON payload for a remote inference service.
        """
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
            "tcp_flags": self.tcp_flags,
            "window_size": self.window_size,
            "direction": self.direction.value,
            "flow_id": self.flow_id,
            "flow_duration": self.flow_duration,
            "connection_state": self.connection_state.value,
            "total_packets_in_flow": self.total_packets_in_flow,
            "total_bytes": self.total_bytes,
            "avg_packet_size": self.avg_packet_size,
            "payload_size": self.payload_size,
            "packet_arrival_time": self.packet_arrival_time,
            "inter_arrival_time": self.inter_arrival_time,
            "packet_rate": self.packet_rate,
            "byte_rate": self.byte_rate,
            "avg_flow_time": self.avg_flow_time,
            "extra": self.extra,
        }

    def __str__(self) -> str:
        """Human-readable one-line summary, useful for logging/debugging."""
        return (
            f"FeatureVector[flow={self.flow_id} {self.protocol} "
            f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port} "
            f"dir={self.direction.value} state={self.connection_state.value} "
            f"len={self.packet_length} pkt#={self.total_packets_in_flow}]"
        )
