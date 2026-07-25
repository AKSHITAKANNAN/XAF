"""
flow_builder.py (Module 2)
----------------------------
Maintains the running statistical state of a single network flow and
updates it, one packet at a time.

WHY THIS FILE EXISTS
Per-packet features (e.g. packet_length) are trivial to extract, but
several required features -- total_packets_in_flow, avg_packet_size,
inter_arrival_time, packet_rate -- only make sense in the context of *all*
packets seen so far for that flow. FlowBuilder is the single place
responsible for that running arithmetic, so feature_extractor.py doesn't
have to know how a flow's statistics are computed, only that it can ask
FlowBuilder to update one.

Single Responsibility: FlowBuilder only knows how to mutate a FlowRecord
given a new packet. It does NOT own storage/lifetime of flows across many
packets/sessions -- that responsibility belongs to session_manager.py.

USED BY
- session_manager.py    (owns the dict of FlowRecords, delegates updates here)
- feature_extractor.py  (indirectly, via SessionManager)
"""

from dataclasses import dataclass, field
from typing import Optional

from module2_feature_extraction.models import FlowKey, ConnectionState
from module2_feature_extraction.utils import map_tcp_flags_to_state
from module2_feature_extraction.logger import get_logger

logger = get_logger("module2_feature_extraction.flow_builder")


@dataclass
class FlowRecord:
    """
    Mutable, in-memory accumulator of everything we know about one flow.

    This is intentionally NOT the same object as FeatureVector: FlowRecord
    is internal bookkeeping state, while FeatureVector is the immutable,
    AI-facing snapshot produced for each individual packet (see
    feature_extractor.py).

    Attributes:
        flow_key: Canonical, direction-independent identity of this flow.
        flow_id: Short hash-based identifier derived from flow_key.
        start_time: Timestamp of the first packet seen in this flow.
        last_seen_time: Timestamp of the most recently seen packet.
        total_packets: Count of packets observed in this flow so far.
        total_bytes: Sum of packet_length across all packets in this flow.
        connection_state: Most recently derived ConnectionState.
        initiator_ip: Source IP of the very first packet in the flow
            (kept for potential future direction/role analysis).
    """
    flow_key: FlowKey
    flow_id: str
    start_time: float
    last_seen_time: float
    total_packets: int = 0
    total_bytes: int = 0
    connection_state: ConnectionState = ConnectionState.UNKNOWN
    initiator_ip: str = ""

    def duration(self) -> float:
        """Seconds elapsed between the first and most recent packet."""
        return max(self.last_seen_time - self.start_time, 0.0)

    def avg_packet_size(self) -> float:
        """Mean packet size (bytes) across all packets seen in this flow."""
        if self.total_packets == 0:
            return 0.0
        return self.total_bytes / self.total_packets

    def packet_rate(self) -> float:
        """Packets per second observed in this flow so far."""
        duration = self.duration()
        if duration <= 0:
            # A single packet (or two packets with identical timestamps)
            # has no meaningful rate yet; avoid division by zero.
            return float(self.total_packets) if self.total_packets else 0.0
        return self.total_packets / duration

    def byte_rate(self) -> float:
        """Bytes per second observed in this flow so far."""
        duration = self.duration()
        if duration <= 0:
            return float(self.total_bytes) if self.total_bytes else 0.0
        return self.total_bytes / duration


class FlowBuilder:
    """
    Stateless service object that knows how to create and update FlowRecord
    instances. Holds no data itself -- all state lives in the FlowRecord
    passed in, which keeps this class trivially unit-testable.
    """

    def create_flow(self, flow_key: FlowKey, flow_id: str, timestamp: float,
                     src_ip: str) -> FlowRecord:
        """
        Construct a brand-new FlowRecord for a flow's first observed packet.

        Args:
            flow_key: Canonical identity of the new flow.
            flow_id: Pre-computed short ID for the flow.
            timestamp: Timestamp of the first packet.
            src_ip: Source IP of the first packet (the flow "initiator").

        Returns:
            A freshly initialized FlowRecord (zero packets/bytes so far --
            the caller is expected to immediately call update_with_packet()).
        """
        return FlowRecord(
            flow_key=flow_key,
            flow_id=flow_id,
            start_time=timestamp,
            last_seen_time=timestamp,
            initiator_ip=src_ip,
        )

    def update_with_packet(self, flow_record: FlowRecord, packet_length: int,
                            timestamp: float, protocol: str,
                            tcp_flags: Optional[str]) -> float:
        """
        Fold one new packet's data into an existing FlowRecord's running
        statistics.

        Args:
            flow_record: The FlowRecord to mutate (created via create_flow
                for a brand new flow, or fetched from SessionManager for an
                existing one).
            packet_length: Length in bytes of the current packet.
            timestamp: Capture timestamp of the current packet.
            protocol: Transport protocol string, used to derive connection state.
            tcp_flags: Raw TCP flags string if available, else None.

        Returns:
            The inter-arrival time (seconds) between this packet and the
            previous packet in the same flow. This is returned directly
            (rather than only stored) because feature_extractor.py needs
            it as a per-packet FeatureVector field.
        """
        try:
            inter_arrival_time = max(timestamp - flow_record.last_seen_time, 0.0)

            flow_record.total_packets += 1
            flow_record.total_bytes += packet_length
            flow_record.last_seen_time = timestamp
            flow_record.connection_state = map_tcp_flags_to_state(tcp_flags, protocol)

            return inter_arrival_time
        except Exception as exc:
            # A single malformed update should never crash the whole
            # pipeline; log it and fall back to a neutral value.
            logger.error("Failed to update flow record %s: %s", flow_record.flow_id, exc)
            return 0.0
