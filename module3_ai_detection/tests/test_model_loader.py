import os
import pytest
from module3_ai_detection.model_loader import save_model, load_model, model_exists
from module3_ai_detection.exceptions import ModelLoadError, ModelSaveError

def test_model_loader_save_load_exists(tmp_path):
    model_path = str(tmp_path / "sub_dir" / "test_model.joblib")
    assert not model_exists(model_path)

    dummy_data = {"key": "value", "weights": [0.1, 0.2, 0.3]}
    save_model(dummy_data, model_path)

    assert model_exists(model_path)
    loaded = load_model(model_path)
    assert loaded == dummy_data

def test_load_non_existent():
    with pytest.raises(ModelLoadError):
        load_model("/path/to/non_existent_file_xyz.joblib")
