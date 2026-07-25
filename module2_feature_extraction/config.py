"""
config.py (Module 2)
---------------------
Centralized configuration for the Feature Extraction Engine.

WHY THIS FILE EXISTS
Clean architecture keeps "policy" (tunable numbers/settings) separate from
"mechanism" (the classes that do the work). Every other file in Module 2
reads its tunable values from a FeatureExtractionConfig instance instead of
hard-coding constants, so behavior can be changed in one place without
touching business logic.

USED BY
- flow_builder.py   (flow inactivity timeout)
- session_manager.py (flow expiry / cleanup interval)
- utils.py          (home network ranges for direction detection)
- feature_extractor.py (top-level wiring; accepts a config override)
"""

from dataclasses import dataclass, field
from typing import List
import logging


@dataclass(frozen=True)
class FeatureExtractionConfig:
    """
    Immutable configuration object for the Feature Extraction Engine.

    Attributes:
        home_networks: CIDR ranges considered "internal"/"local" to this
            host or network. Used to classify each packet's direction as
            OUTBOUND (traffic leaving the home network) or INBOUND
            (traffic entering it). Defaults cover the standard private
            IPv4 ranges (RFC 1918).
        flow_timeout_seconds: How long (in seconds) a flow may sit idle
            before the SessionManager considers it expired/closed. This
            bounds memory usage and lets us compute meaningful flow
            durations instead of tracking flows forever.
        max_tracked_flows: Safety cap on the number of concurrent flows
            the SessionManager will track in memory. Prevents unbounded
            memory growth under high traffic or a scanning/DoS scenario.
        cleanup_interval_seconds: Minimum time between automatic expired-flow
            sweeps triggered by the FeatureExtractionEngine, to avoid
            scanning the whole flow table on every single packet.
        log_level: Default logging verbosity for Module 2 components.
    """

    home_networks: List[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    )
    flow_timeout_seconds: float = 60.0
    max_tracked_flows: int = 100_000
    cleanup_interval_seconds: float = 5.0
    log_level: int = logging.INFO


# A ready-to-use default configuration instance. Other modules may import
# this directly, or construct their own FeatureExtractionConfig(...) for
# custom deployments/tests.
DEFAULT_CONFIG = FeatureExtractionConfig()
