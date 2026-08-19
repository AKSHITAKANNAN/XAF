import pytest
import numpy as np
import pandas as pd
from module3_ai_detection.detector import create_model
from module3_ai_detection.trainer import Trainer
from module3_ai_detection.exceptions import TrainingDataError

def test_trainer_train_and_evaluate(tmp_path):
    model = create_model("random_forest", n_estimators=10, random_state=42)
    trainer = Trainer(model=model)
    
    # Create a dummy CSV dataset
    csv_file = str(tmp_path / "dummy_dataset.csv")
    df = pd.DataFrame({
        "packet_length": [60, 60, 1500, 1500],
        "flow_duration": [0.1, 0.1, 5.0, 5.0],
        "protocol": ["TCP", "TCP", "UDP", "UDP"],
        "label": ["BENIGN", "BENIGN", "DDOS", "DDOS"]
    })
    df.to_csv(csv_file, index=False)
    
    X, y = trainer.load_dataset_from_csv(csv_file, label_column="label")
    assert len(X) == 4
    assert len(y) == 4
    
    X_train, X_test, y_train, y_test = trainer.train_test_split_and_train(X, y, test_size=0.5, random_state=42)
    metrics = trainer.evaluate(X_test, y_test)
    
    assert "accuracy" in metrics
    assert "classification_report" in metrics

def test_trainer_missing_csv():
    model = create_model("random_forest")
    trainer = Trainer(model=model)
    with pytest.raises(TrainingDataError):
        trainer.load_dataset_from_csv("non_existent_file.csv")
