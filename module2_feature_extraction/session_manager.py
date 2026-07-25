"""
session_manager.py (Module 2)
--------------------------------
Owns the collection of all in-progress flows and their lifecycle
(creation, lookup, expiry, and aggregate statistics across flows).

WHY THIS FILE EXISTS
FlowBuilder (flow_builder.py) knows how to update a *single* FlowRecord: it
has no concept of "all the flows currently being tracked", how long they've
been idle, or when to forget them. SessionManager is that missing layer --
it is the only place in Module 2 that owns a dictionary of flows, so
storage/expiry policy lives in exactly one class (Single Responsibility).

Thread-safety: sniffing callbacks in Module 1 can fire from a background
thread, so all mutations of the internal flow table are guarded by a lock.

USED BY
- feature_extractor.py (the only class that talks to SessionManager directly)
"""

import threading
from typing import Dict, Optional

from module2_feature_extraction.config import FeatureExtractionConfig, DEFAULT_CONFIG
from module2_feature_extraction.flow_builder import FlowBuilder, FlowRecord
from module2_feature_extraction.models import FlowKey
from module2_feature_extraction.logger import get_logger

logger = get_logger("module2_feature_extraction.session_manager")


class SessionManager:
    """
    Thread-safe registry of active flows, backed by an in-memory dict.

    Responsibilities:
      - Create a new FlowRecord the first time a FlowKey is seen.
      - Return the existing FlowRecord on subsequent packets of the same flow.
      - Periodically expire flows that have been idle longer than
        config.flow_timeout_seconds, freeing memory and finalizing their
        duration for the running average-flow-time statistic.
      - Track aggregate statistics (e.g. average flow duration) across all
        flows ever observed, not just the currently active ones.
    """

    def __init__(self, config: Optional[FeatureExtractionConfig] = None,
                 flow_builder: Optional[FlowBuilder] = None):
        """
        Args:
            config: Configuration controlling timeout/capacity behavior.
                Defaults to config.DEFAULT_CONFIG if not provided.
            flow_builder: The FlowBuilder used to create/update FlowRecords.
                Injected (rather than hard-coded) to keep this class easy
                to unit test with a fake/mock builder if ever needed.
        """
        self._config = config or DEFAULT_CONFIG
        self._flow_builder = flow_builder or FlowBuilder()
        self._flows: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.Lock()

        # Running aggregate used to compute avg_flow_time across *closed*
        # (expired) flows, so this statistic reflects real completed
        # conversations rather than only currently-open ones.
        self._closed_flow_duration_sum: float = 0.0
        self._closed_flow_count: int = 0

        self._last_cleanup_time: float = 0.0

    def get_or_create_flow(self, flow_key: FlowKey, flow_id: str,
                            timestamp: float, src_ip: str) -> FlowRecord:
        """
        Fetch the FlowRecord for flow_key, creating it if this is the first
        packet ever seen for that flow.

        Args:
            flow_key: Canonical identity of the flow.
            flow_id: Pre-computed short ID for the flow.
            timestamp: Timestamp of the current packet (used as start_time
                if a new flow must be created).
            src_ip: Source IP of the current packet (recorded as the flow
                initiator only when creating a new flow).

        Returns:
            The (possibly newly created) FlowRecord for this flow.
        """
        with self._lock:
            flow_record = self._flows.get(flow_key)
            if flow_record is None:
                if len(self._flows) >= self._config.max_tracked_flows:
                    logger.warning(
                        "max_tracked_flows (%d) reached; evicting oldest flow.",
                        self._config.max_tracked_flows,
                    )
                    self._evict_oldest_locked()

                flow_record = self._flow_builder.create_flow(
                    flow_key, flow_id, timestamp, src_ip
                )
                self._flows[flow_key] = flow_record
                logger.debug("Created new flow %s", flow_id)

            return flow_record

    def _evict_oldest_locked(self) -> None:
        """
        Remove the least-recently-active flow to make room for a new one.

        Must be called while holding self._lock. Kept as a separate method
        for readability/testability of the eviction policy in isolation.
        """
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].last_seen_time)
        del self._flows[oldest_key]

    def cleanup_expired_flows(self, now: float) -> int:
        """
        Remove flows that have been idle longer than flow_timeout_seconds,
        folding their final duration into the running average-flow-time
        statistic before discarding them.

        Args:
            now: Current timestamp to compare against each flow's
                last_seen_time.

        Returns:
            The number of flows removed by this call.
        """
        with self._lock:
            expired_keys = [
                key for key, record in self._flows.items()
                if (now - record.last_seen_time) > self._config.flow_timeout_seconds
            ]

            for key in expired_keys:
                record = self._flows.pop(key)
                self._closed_flow_duration_sum += record.duration()
                self._closed_flow_count += 1
                logger.debug("Expired flow %s after %.2fs idle.",
                             record.flow_id, now - record.last_seen_time)

            self._last_cleanup_time = now
            return len(expired_keys)

    def maybe_cleanup(self, now: float) -> None:
        """
        Run cleanup_expired_flows only if at least
        config.cleanup_interval_seconds has elapsed since the last sweep.

        This lets feature_extractor.py call this on every packet without
        paying the cost of a full table scan per-packet under high traffic.

        Args:
            now: Current timestamp.
        """
        if (now - self._last_cleanup_time) >= self._config.cleanup_interval_seconds:
            self.cleanup_expired_flows(now)

    def get_active_flow_count(self) -> int:
        """Return how many flows are currently being tracked (not expired)."""
        with self._lock:
            return len(self._flows)

    def get_avg_flow_time(self) -> float:
        """
        Return the running average duration (seconds) across all flows,
        combining both:
          - flows already closed/expired (their final duration), and
          - flows still active (their current duration so far),
        so the statistic is meaningful even before any flow has expired.

        Returns:
            Average flow duration in seconds, or 0.0 if no flows exist yet.
        """
        with self._lock:
            active_durations = [record.duration() for record in self._flows.values()]
            total_duration = self._closed_flow_duration_sum + sum(active_durations)
            total_count = self._closed_flow_count + len(active_durations)

            if total_count == 0:
                return 0.0
            return total_duration / total_count

    def clear(self) -> None:
        """Remove all tracked flows and reset aggregate statistics (test helper)."""
        with self._lock:
            self._flows.clear()
            self._closed_flow_duration_sum = 0.0
            self._closed_flow_count = 0
            self._last_cleanup_time = 0.0
