import time
import pytest
from module3_ai_detection.models import (
    AttackCategory,
    ThreatLabel,
    Severity,
    ThreatPrediction,
)

def test_enums():
    assert AttackCategory.BENIGN.value == "BENIGN"
    assert AttackCategory.DDOS.value == "DDOS"
    assert ThreatLabel.MALICIOUS.value == "MALICIOUS"
    assert Severity.CRITICAL.value == "CRITICAL"

def test_threat_prediction_to_dict():
    now = time.time()
    tp = ThreatPrediction(
        threat_label=ThreatLabel.MALICIOUS,
        confidence_score=95.0,
        risk_score=95.0,
        severity=Severity.CRITICAL,
        attack_category=AttackCategory.DDOS,
        model_name="random_forest",
        prediction_timestamp=now,
    )
    d = tp.to_dict()
    assert d["threat_label"] == "MALICIOUS"
    assert d["attack_category"] == "DDOS"
    assert d["severity"] == "CRITICAL"
    assert "ThreatPrediction[" in str(tp)
