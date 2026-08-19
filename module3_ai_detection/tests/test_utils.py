import pytest
from module3_ai_detection.config import DEFAULT_CONFIG
from module3_ai_detection.models import AttackCategory, Severity, ThreatLabel
from module3_ai_detection.utils import (
    classify_severity,
    derive_threat_label,
    compute_risk_score,
    normalize_category_label,
)

def test_classify_severity():
    thresholds = DEFAULT_CONFIG.severity_thresholds
    assert classify_severity(10.0, thresholds) == Severity.LOW
    assert classify_severity(30.0, thresholds) == Severity.LOW
    assert classify_severity(50.0, thresholds) == Severity.MEDIUM
    assert classify_severity(70.0, thresholds) == Severity.MEDIUM
    assert classify_severity(80.0, thresholds) == Severity.HIGH
    assert classify_severity(90.0, thresholds) == Severity.HIGH
    assert classify_severity(95.0, thresholds) == Severity.CRITICAL

def test_derive_threat_label():
    assert derive_threat_label(AttackCategory.BENIGN, 99.0) == ThreatLabel.BENIGN
    assert derive_threat_label(AttackCategory.UNKNOWN, 50.0) == ThreatLabel.UNKNOWN
    assert derive_threat_label(AttackCategory.PORT_SCAN, 30.0) == ThreatLabel.SUSPICIOUS
    assert derive_threat_label(AttackCategory.PORT_SCAN, 80.0) == ThreatLabel.MALICIOUS

def test_compute_risk_score():
    r_exfil = compute_risk_score(90.0, AttackCategory.DATA_EXFILTRATION, DEFAULT_CONFIG)
    r_scan = compute_risk_score(90.0, AttackCategory.PORT_SCAN, DEFAULT_CONFIG)
    assert r_exfil > r_scan

def test_normalize_category_label():
    assert normalize_category_label("ddos") == AttackCategory.DDOS
    assert normalize_category_label("Port-Scan") == AttackCategory.PORT_SCAN
    assert normalize_category_label("Unknown_Category_XYZ") == AttackCategory.UNKNOWN
