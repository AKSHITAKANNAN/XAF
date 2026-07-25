"""
module3_ai_detection
-----------------------
Package marker for Module 3 (AI Threat Detection Engine) of the
XAF: Next-Gen AI Firewall with Smart Response project.

Public entry point for other code (e.g. a future Smart Response /
Explainability module) is InferenceEngine, exposed here for convenience:

    from module3_ai_detection import InferenceEngine, ThreatPrediction
"""

from module3_ai_detection.inference import InferenceEngine
from module3_ai_detection.models import (
    ThreatPrediction, ThreatLabel, Severity, AttackCategory,
)
from module3_ai_detection.detector import create_model, BaseThreatModel

__all__ = [
    "InferenceEngine",
    "ThreatPrediction",
    "ThreatLabel",
    "Severity",
    "AttackCategory",
    "create_model",
    "BaseThreatModel",
]
