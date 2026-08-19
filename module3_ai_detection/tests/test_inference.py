import time
import pytest
from module2_feature_extraction.models import FeatureVector, PacketDirection, ConnectionState
from module3_ai_detection.detector import create_model
from module3_ai_detection.inference import InferenceEngine
from module3_ai_detection.run_detection import bootstrap_demo_model, build_sample_feature_vector
from module3_ai_detection.config import DEFAULT_CONFIG
from module3_ai_detection.models import ThreatLabel, Severity, AttackCategory
from module3_ai_detection.exceptions import ModelNotLoadedError, InvalidFeatureVectorError

def test_inference_engine_predict():
    model = bootstrap_demo_model(DEFAULT_CONFIG)
    engine = InferenceEngine(model=model, config=DEFAULT_CONFIG)
    
    fv = build_sample_feature_vector()
    prediction = engine.predict(fv)
    
    assert prediction.threat_label in [ThreatLabel.BENIGN, ThreatLabel.SUSPICIOUS, ThreatLabel.MALICIOUS, ThreatLabel.UNKNOWN]
    assert 0.0 <= prediction.confidence_score <= 100.0
    assert 0.0 <= prediction.risk_score <= 100.0
    assert prediction.model_name == "random_forest"

def test_inference_engine_unloaded_model():
    model = create_model("random_forest")
    engine = InferenceEngine(model=model)
    fv = build_sample_feature_vector()
    with pytest.raises(ModelNotLoadedError):
        engine.predict(fv)

def test_inference_engine_invalid_input():
    model = bootstrap_demo_model(DEFAULT_CONFIG)
    engine = InferenceEngine(model=model)
    with pytest.raises(InvalidFeatureVectorError):
        engine.predict(None)
