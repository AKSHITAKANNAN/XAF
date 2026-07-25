"""
feature_extractor.py (Module 2)
----------------------------------
Top-level orchestrator of the Feature Extraction Engine. This is the ONLY
class other modules (Module 1's callback, Module 3, the example runner)
need to talk to directly.

WHY THIS FILE EXISTS
Clean architecture: this is the "use case" layer. It coordinates the
lower-level building blocks (utils, FlowBuilder, SessionManager) into the
single operation the rest of the system actually needs: "given a packet,
give me a feature vector." It contains no low-level arithmetic itself and
no direct network/Scapy access -- that separation is what makes each piece
independently testable.

INPUT:  module1_packet_capture.models.PacketData (Module 1's output type)
OUTPUT: module2_feature_extraction.models.FeatureVector

This module does NOT perform detection, scoring, blocking, or dashboarding
of any kind -- only feature extraction, per the Module 2 specification.

USED BY
- examples/run_feature_extraction.py
- Module 3 (future AI Detection Engine) -- consumes FeatureVector output
"""

from typing import List, Optional

# NOTE: This is the one and only integration point with Module 1. Module 2
# depends on Module 1's PacketData type as its input contract, but does not
# import or rely on any of Module 1's internal implementation details.
from module1_packet_capture.models import PacketData

from module2_feature_extraction.config import FeatureExtractionConfig, DEFAULT_CONFIG
from module2_feature_extraction.models import FeatureVector, ConnectionState
from module2_feature_extraction.flow_builder import FlowBuilder
from module2_feature_extraction.session_manager import SessionManager
from module2_feature_extraction.utils import (
    compute_flow_key,
    generate_flow_id,
    determine_direction,
    safe_get_extra,
    estimate_payload_size,
)
from module2_feature_extraction.logger import get_logger

logger = get_logger("module2_feature_extraction.feature_extractor")


class FeatureExtractionError(Exception):
    """Raised when a PacketData object cannot be converted into a FeatureVector."""


class FeatureExtractionEngine:
    """
    Converts live PacketData objects (from Module 1) into AI-ready
    FeatureVector objects, maintaining per-flow context along the way.

    Typical usage, wired directly into Module 1's capture callback:

        from module1_packet_capture import PacketCaptureEngine
        from module2_feature_extraction import FeatureExtractionEngine

        engine = FeatureExtractionEngine()

        def on_packet(packet_data):
            feature_vector = engine.extract(packet_data)
            print(feature_vector)

        capture = PacketCaptureEngine(on_packet=on_packet)
        capture.start(packet_count=50)
    """

    def __init__(self, config: Optional[FeatureExtractionConfig] = None,
                 session_manager: Optional[SessionManager] = None,
                 flow_builder: Optional[FlowBuilder] = None):
        """
        Args:
            config: Tunable settings (see config.py). Defaults to DEFAULT_CONFIG.
            session_manager: Injected SessionManager instance. A new one is
                created if not provided -- but callers processing multiple
                packet streams that should share flow state (e.g. tests)
                may inject a shared instance.
            flow_builder: Injected FlowBuilder instance (rarely needs
                overriding; exposed mainly for testability).
        """
        self._config = config or DEFAULT_CONFIG
        self._flow_builder = flow_builder or FlowBuilder()
        self._session_manager = session_manager or SessionManager(
            config=self._config, flow_builder=self._flow_builder
        )

    def extract(self, packet_data: PacketData) -> FeatureVector:
        """
        Convert a single PacketData object into a FeatureVector.

        Args:
            packet_data: A packet as produced by Module 1's
                PacketCaptureEngine (already validated / non-corrupted).

        Returns:
            A fully populated FeatureVector.

        Raises:
            FeatureExtractionError: If packet_data is missing required
                fields or is otherwise unusable. Callers (e.g. the Module 1
                capture callback) should catch this so one bad packet never
                stops the pipeline.
        """
        if packet_data is None:
            raise FeatureExtractionError("packet_data must not be None.")

        try:
            protocol = (
                packet_data.protocol.value
                if hasattr(packet_data.protocol, "value")
                else str(packet_data.protocol)
            )

            # ---- Flow identity & state -----------------------------------
            flow_key = compute_flow_key(
                packet_data.src_ip, packet_data.src_port,
                packet_data.dst_ip, packet_data.dst_port,
                protocol,
            )
            flow_id = generate_flow_id(flow_key)

            now = packet_data.timestamp
            self._session_manager.maybe_cleanup(now)

            flow_record = self._session_manager.get_or_create_flow(
                flow_key, flow_id, now, packet_data.src_ip
            )

            tcp_flags = safe_get_extra(packet_data.extra, "tcp_flags")
            inter_arrival_time = self._flow_builder.update_with_packet(
                flow_record, packet_data.length, now, protocol, tcp_flags
            )

            # First packet of a brand-new flow has no meaningful predecessor.
            if flow_record.total_packets <= 1:
                inter_arrival_time = None

            # ---- Advanced / per-packet metadata ----------------------------
            ttl = safe_get_extra(packet_data.extra, "ttl")
            window_size = safe_get_extra(packet_data.extra, "window_size")
            payload_size = safe_get_extra(
                packet_data.extra, "payload_size",
                default=estimate_payload_size(packet_data.length, protocol),
            )
            direction = determine_direction(
                packet_data.src_ip, packet_data.dst_ip, self._config.home_networks
            )

            feature_vector = FeatureVector(
                # Basic Features
                src_ip=packet_data.src_ip,
                dst_ip=packet_data.dst_ip,
                src_port=packet_data.src_port,
                dst_port=packet_data.dst_port,
                protocol=protocol,
                packet_length=packet_data.length,
                timestamp=packet_data.timestamp,
                # Advanced Features
                ttl=ttl,
                tcp_flags=tcp_flags,
                window_size=window_size,
                direction=direction,
                flow_id=flow_id,
                flow_duration=flow_record.duration(),
                connection_state=flow_record.connection_state,
                total_packets_in_flow=flow_record.total_packets,
                total_bytes=flow_record.total_bytes,
                avg_packet_size=flow_record.avg_packet_size(),
                payload_size=payload_size,
                packet_arrival_time=packet_data.timestamp,
                inter_arrival_time=inter_arrival_time,
                # Statistics
                packet_rate=flow_record.packet_rate(),
                byte_rate=flow_record.byte_rate(),
                avg_flow_time=self._session_manager.get_avg_flow_time(),
            )

            logger.debug("Extracted %s", feature_vector)
            return feature_vector

        except FeatureExtractionError:
            raise
        except Exception as exc:
            logger.error("Failed to extract features from packet: %s", exc)
            raise FeatureExtractionError(str(exc)) from exc

    def extract_batch(self, packets: List[PacketData]) -> List[FeatureVector]:
        """
        Convert a list of PacketData objects into FeatureVectors, skipping
        (and logging) any individual packet that fails extraction rather
        than aborting the whole batch.

        Args:
            packets: A list of PacketData objects, e.g. from
                PacketCaptureEngine.get_captured_packets().

        Returns:
            A list of successfully extracted FeatureVector objects (may be
            shorter than the input list if some packets were unusable).
        """
        results: List[FeatureVector] = []
        for packet_data in packets:
            try:
                results.append(self.extract(packet_data))
            except FeatureExtractionError as exc:
                logger.warning("Skipping packet during batch extraction: %s", exc)
        return results

    def get_active_flow_count(self) -> int:
        """Expose the number of currently tracked flows (diagnostics/tests)."""
        return self._session_manager.get_active_flow_count()
