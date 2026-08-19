import os
import pytest
import numpy as np
from module3_ai_detection.detector import (
    create_model,
    RandomForestThreatModel,
)
from module3_ai_detection.exceptions import ModelNotTrainedError, UnsupportedModelError

def test_create_model_random_forest():
    model = create_model("random_forest", n_estimators=10)
    assert isinstance(model, RandomForestThreatModel)
    assert model.model_name == "random_forest"
    assert not model.is_trained

def test_create_model_unsupported():
    with pytest.raises(UnsupportedModelError):
        create_model("xgboost")
        
    with pytest.raises(UnsupportedModelError):
        create_model("non_existent_model")

def test_random_forest_fit_predict_save_load(tmp_path):
    model = create_model("random_forest", n_estimators=10, random_state=42)
    
    # 4 samples, 3 features
    X = np.array([
        [1.0, 2.0, 3.0],
        [1.1, 2.1, 3.1],
        [10.0, 20.0, 30.0],
        [10.1, 20.1, 30.1]
    ])
    y = np.array(["BENIGN", "BENIGN", "DDOS", "DDOS"])
    
    with pytest.raises(ModelNotTrainedError):
        _ = model.classes_
        
    model.fit(X, y)
    assert model.is_trained
    assert set(model.classes_) == {"BENIGN", "DDOS"}
    
    preds = model.predict(X)
    assert len(preds) == 4
    
    probs = model.predict_proba(X)
    assert probs.shape == (4, 2)

    # Save & Load roundtrip
    save_file = str(tmp_path / "rf_model.joblib")
    model.save(save_file)
    
    loaded_model = create_model("random_forest")
    loaded_model.load(save_file)
    assert loaded_model.is_trained
    loaded_preds = loaded_model.predict(X)
    np.testing.assert_array_equal(preds, loaded_preds)
