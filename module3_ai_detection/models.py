"""
models.py (Module 3)
-----------------------
Data structures produced by the AI Threat Detection Engine.

WHY THIS FILE EXISTS
Following the same "entities have no I/O dependencies" rule used in
Modules 1 and 2: these are plain dataclasses/enums with no scikit-learn,
file, or network imports. This is the contract Module 3 hands off to
whatever consumes threat predictions next (a future Smart Response /
Explainability module), so it must stay stable and trivially serializable.

USED BY
- utils.py       (derive_threat_label, classify_severity, compute_risk_score)
- inference.py   (assembles the final ThreatPrediction)
- run_detection.py
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackCategory(str, Enum):
    """
    The specific traffic classes the ML model is trained to recognize.

    This is the fine-grained output of the classifier itself -- exactly
    the class label scikit-learn's `predict()` would return, mapped onto
    a fixed, well-known vocabulary so downstream code never has to deal
    with raw, unvalidated strings.
    """
    BENIGN = "BENIGN"
    PORT_SCAN = "PORT_SCAN"
    DDOS = "DDOS"
    BRUTE_FORCE = "BRUTE_FORCE"
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    BOTNET = "BOTNET"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNKNOWN = "UNKNOWN"


class ThreatLabel(str, Enum):
    """
    Coarse-grained classification of traffic, derived from AttackCategory.

    Kept separate from AttackCategory because many downstream consumers
    (a policy engine, an alert de-duplicator, a human analyst dashboard)
    only care "is this a problem or not", not which of the nine specific
    categories it is. See utils.derive_threat_label() for the mapping rule.
    """
    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    """
    Confidence-driven urgency banding, per the specification:
        0-30   -> LOW
        31-70  -> MEDIUM
        71-90  -> HIGH
        91-100 -> CRITICAL
    See utils.classify_severity() for the exact boundary logic.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatPrediction:
    """
    The sole output type of the AI Threat Detection Engine.

    Attributes:
        threat_label: Coarse classification (BENIGN/MALICIOUS/SUSPICIOUS/UNKNOWN).
        confidence_score: Model's confidence in the predicted attack_category,
            expressed as a percentage (0.0-100.0).
        risk_score: Confidence weighted by how dangerous the predicted
            category typically is (0.0-100.0). Two predictions with equal
            confidence but different attack categories can have different
            risk_score values -- this is intentional (see config.py
            attack_category_risk_weights).
        severity: Urgency band derived from confidence_score.
        attack_category: The specific predicted traffic class.
        model_name: Identifier of the model that produced this prediction
            (e.g. "random_forest"), for auditability when multiple model
            types may be in use across a deployment.
        prediction_timestamp: Unix epoch timestamp of when this prediction
            was produced.
    """
    threat_label: ThreatLabel
    confidence_score: float
    risk_score: float
    severity: Severity
    attack_category: AttackCategory
    model_name: str
    prediction_timestamp: float

    # Free-form slot for anything a future module wants to attach (e.g. the
    # raw per-class probability distribution) without breaking this
    # dataclass's schema. Mirrors the `extra` pattern used in Modules 1 & 2.
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Serialize this ThreatPrediction into a plain dictionary.

        This is the hand-off format for whatever consumes AI detection
        results next (logging, alerting, a future policy/response module),
        since dicts convert trivially into JSON or a DataFrame row.
        """
        return {
            "threat_label": self.threat_label.value,
            "confidence_score": self.confidence_score,
            "risk_score": self.risk_score,
            "severity": self.severity.value,
            "attack_category": self.attack_category.value,
            "model_name": self.model_name,
            "prediction_timestamp": self.prediction_timestamp,
            "extra": self.extra,
        }

    def __str__(self) -> str:
        """Human-readable one-line summary, useful for logging/debugging."""
        return (
            f"ThreatPrediction[label={self.threat_label.value} "
            f"category={self.attack_category.value} "
            f"confidence={self.confidence_score:.2f}% "
            f"risk={self.risk_score:.2f} "
            f"severity={self.severity.value} "
            f"model={self.model_name}]"
        )
