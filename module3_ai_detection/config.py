"""
config.py (Module 3)
-----------------------
Centralized configuration for the AI Threat Detection Engine.

WHY THIS FILE EXISTS
Clean architecture keeps "policy" (tunable numbers/paths/thresholds)
separate from "mechanism" (the classes that do the work). Every other
Module 3 file reads its tunable values from a DetectionConfig instance
instead of hard-coding constants, so behavior -- which model is active,
where it's persisted, what counts as HIGH severity -- can be changed in
one place without touching business logic.

No path in this file is an absolute, hard-coded filesystem path: the
model location is built from a configurable directory + filename, both
of which default to project-relative values and can be overridden by the
caller (e.g. via environment variables or explicit constructor arguments)
to satisfy the "no hardcoded paths" coding rule.

USED BY
- detector.py       (supported_models / default_model for the model factory)
- model_loader.py   (indirectly, via the path passed to save()/load())
- trainer.py        (model_path, default_model)
- inference.py       (confidence_thresholds, attack_category_risk_weights)
- run_detection.py  (top-level wiring)
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import logging


@dataclass(frozen=True)
class DetectionConfig:
    """
    Immutable configuration object for the AI Threat Detection Engine.

    Attributes:
        model_directory: Directory where trained model artifacts are
            persisted/loaded from. Defaults to a "trained_models" folder
            relative to the current working directory, but is fully
            overridable (e.g. `DetectionConfig(model_directory="/opt/xaf/models")`)
            -- nothing in the rest of Module 3 hard-codes this path.
        model_filename: Filename (not full path) of the active model's
            serialized artifact.
        default_model: Which model implementation is active by default.
            Must be a key in `supported_models`.
        supported_models: The full set of model identifiers the
            architecture is designed to support via detector.py's model
            factory. Only "random_forest" is implemented today; the rest
            are reserved names for future drop-in implementations.
        confidence_thresholds: Ordered (label, upper_bound_inclusive) pairs
            defining the Severity bands, evaluated in order. A confidence
            of 25 matches the first band whose upper bound is >= 25.
        attack_category_risk_weights: Multiplier applied to confidence_score
            to compute risk_score, reflecting that some attack categories
            are inherently more dangerous than others even at equal model
            confidence (e.g. DATA_EXFILTRATION should read as riskier than
            PORT_SCAN at the same confidence level).
        log_level: Default logging verbosity for Module 3 components.
    """

    model_directory: str = field(default_factory=lambda: os.environ.get(
        "XAF_MODEL_DIR", os.path.join(os.getcwd(), "trained_models")
    ))
    model_filename: str = "random_forest_threat_model.joblib"

    default_model: str = "random_forest"
    supported_models: Tuple[str, ...] = (
        "random_forest",
        "xgboost",
        "lightgbm",
        "catboost",
        "neural_network",
        "isolation_forest",
    )

    # (severity_label, upper_bound_inclusive) evaluated in ascending order.
    confidence_thresholds: Tuple[Tuple[str, float], ...] = (
        ("LOW", 30.0),
        ("MEDIUM", 70.0),
        ("HIGH", 90.0),
        ("CRITICAL", 100.0),
    )

    attack_category_risk_weights: Dict[str, float] = field(default_factory=lambda: {
        "BENIGN": 0.0,
        "PORT_SCAN": 0.55,
        "BRUTE_FORCE": 0.70,
        "PHISHING": 0.75,
        "BOTNET": 0.85,
        "MALWARE": 0.90,
        "DDOS": 0.90,
        "DATA_EXFILTRATION": 0.95,
        "UNKNOWN": 0.50,
    })

    log_level: int = logging.INFO

    @property
    def model_path(self) -> str:
        """Full path (directory + filename) to the active model artifact."""
        return os.path.join(self.model_directory, self.model_filename)


# A ready-to-use default configuration instance. Other modules may import
# this directly, or construct their own DetectionConfig(...) for custom
# deployments, experiments, or tests.
DEFAULT_CONFIG = DetectionConfig()
