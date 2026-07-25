"""
utils.py (Module 3)
----------------------
Stand-alone helper functions for the AI Threat Detection Engine.

WHY THIS FILE EXISTS
Pure functions with no class state are the easiest thing in the codebase
to unit test and reuse. Keeping severity/risk-score arithmetic here (rather
than buried inside inference.py) means it can be tested directly and
reused elsewhere (e.g. by a future batch-reporting tool) without
instantiating the full inference pipeline.

USED BY
- inference.py (classify_severity, compute_risk_score, derive_threat_label, get_timestamp)
"""

import time
from typing import Tuple

from module3_ai_detection.models import AttackCategory, Severity, ThreatLabel
from module3_ai_detection.config import DetectionConfig


def get_timestamp() -> float:
    """
    Return the current time as a Unix epoch timestamp (float seconds).

    Wrapped in its own function so timestamp generation can be mocked in
    tests, or later swapped for an NTP-synced clock if needed.
    """
    return time.time()


def classify_severity(confidence_score: float,
                       thresholds: Tuple[Tuple[str, float], ...]) -> Severity:
    """
    Map a confidence score (0-100) onto a Severity band.

    Args:
        confidence_score: Model confidence as a percentage (0.0-100.0).
        thresholds: Ordered (severity_label, upper_bound_inclusive) pairs,
            evaluated in ascending order (see config.DetectionConfig).
            Per the specification:
                0-30   -> LOW
                31-70  -> MEDIUM
                71-90  -> HIGH
                91-100 -> CRITICAL

    Returns:
        The Severity enum value for the first threshold band whose
        upper bound is >= confidence_score. Falls back to the highest
        band (CRITICAL) if confidence_score exceeds every configured bound.
    """
    clamped = max(0.0, min(confidence_score, 100.0))

    for label, upper_bound in thresholds:
        if clamped <= upper_bound:
            return Severity(label)

    # Defensive fallback: if thresholds don't cover 100 for some reason,
    # anything above the highest configured bound is still CRITICAL.
    return Severity.CRITICAL


def derive_threat_label(attack_category: AttackCategory,
                         confidence_score: float,
                         suspicious_confidence_ceiling: float = 50.0) -> ThreatLabel:
    """
    Derive a coarse ThreatLabel from the model's specific AttackCategory
    prediction and its confidence.

    Rules:
        - BENIGN category            -> ThreatLabel.BENIGN
        - UNKNOWN category           -> ThreatLabel.UNKNOWN
        - Any other category, but
          confidence below the
          suspicious ceiling         -> ThreatLabel.SUSPICIOUS
          (the model leans toward an attack class but isn't confident
          enough to call it definitively malicious)
        - Any other category, with
          confidence at/above the
          suspicious ceiling         -> ThreatLabel.MALICIOUS

    Args:
        attack_category: The specific predicted traffic class.
        confidence_score: Model confidence as a percentage (0.0-100.0).
        suspicious_confidence_ceiling: Confidence threshold below which a
            non-benign, non-unknown prediction is treated as merely
            SUSPICIOUS rather than definitively MALICIOUS.

    Returns:
        The derived ThreatLabel.
    """
    if attack_category == AttackCategory.BENIGN:
        return ThreatLabel.BENIGN
    if attack_category == AttackCategory.UNKNOWN:
        return ThreatLabel.UNKNOWN
    if confidence_score < suspicious_confidence_ceiling:
        return ThreatLabel.SUSPICIOUS
    return ThreatLabel.MALICIOUS


def compute_risk_score(confidence_score: float, attack_category: AttackCategory,
                        config: DetectionConfig) -> float:
    """
    Compute a risk_score (0-100) from model confidence and the predicted
    attack category's inherent danger weight.

    Two predictions with identical confidence but different attack
    categories should not be treated as equally risky -- e.g. a 90%
    confident PORT_SCAN is reconnaissance, while a 90% confident
    DATA_EXFILTRATION is an active breach. This function encodes that
    distinction via config.attack_category_risk_weights.

    Args:
        confidence_score: Model confidence as a percentage (0.0-100.0).
        attack_category: The specific predicted traffic class.
        config: DetectionConfig supplying the per-category risk weights.

    Returns:
        Risk score in the range 0.0-100.0.
    """
    clamped_confidence = max(0.0, min(confidence_score, 100.0))
    weight = config.attack_category_risk_weights.get(attack_category.value, 0.5)
    risk = clamped_confidence * weight
    return max(0.0, min(risk, 100.0))


def normalize_category_label(raw_label: str) -> AttackCategory:
    """
    Safely convert an arbitrary raw string (e.g. a model's predicted class
    label, or a training dataset's label column value) into an
    AttackCategory enum member.

    Args:
        raw_label: Raw label text, typically from `model.classes_` or a
            CSV label column. Matching is case-insensitive and tolerant of
            surrounding whitespace, since real-world datasets are messy.

    Returns:
        The matching AttackCategory, or AttackCategory.UNKNOWN if the raw
        label doesn't correspond to any known category. This function
        never raises -- an unrecognized label is a data-quality signal to
        surface downstream (e.g. via logging), not a reason to crash.
    """
    if not raw_label:
        return AttackCategory.UNKNOWN

    normalized = raw_label.strip().upper().replace("-", "_").replace(" ", "_")
    for category in AttackCategory:
        if category.value == normalized:
            return category
    return AttackCategory.UNKNOWN
