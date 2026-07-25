"""
trainer.py (Module 3)
------------------------
Trains a BaseThreatModel (Random Forest by default) from a labeled CSV
dataset, and provides evaluation, save, load, and batch-predict helpers.

WHY THIS FILE EXISTS
Model training is a distinct concern from model inference: training reads
historical, labeled data in bulk and fits an estimator, while inference
(inference.py) takes one live FeatureVector at a time through an already
-trained model. Separating them means the live detection path never
imports pandas or touches the filesystem for a CSV, keeping it lean and
fast.

DATASET COMPATIBILITY
This trainer works against any CSV export that provides Module 3's
expected feature columns (see feature_mapper.FEATURE_ORDER) plus one
label column. It is designed to be adaptable to common public
intrusion-detection datasets such as CICIDS2017, CSE-CIC-IDS2018,
UNSW-NB15, and TON_IoT -- each of which uses a different label column
name and different raw feature column names, so `label_column` and
`column_mapping` are both configurable rather than hard-coded.

No dataset files are bundled with this module -- the caller must supply
their own CSV path.

USED BY
- run_detection.py (optionally, to bootstrap a demo model)
- A separate, manually-run training script/notebook in a real deployment
"""

import os
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, classification_report,
)
from sklearn.model_selection import train_test_split

from module3_ai_detection.detector import BaseThreatModel
from module3_ai_detection.preprocessor import Preprocessor
from module3_ai_detection.feature_mapper import FEATURE_ORDER, CATEGORICAL_FEATURES
from module3_ai_detection.utils import normalize_category_label
from module3_ai_detection.exceptions import TrainingDataError, ModelNotTrainedError
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.trainer")


class Trainer:
    """
    Orchestrates training, evaluation, and persistence of a BaseThreatModel
    from a labeled CSV dataset.

    Dependencies (the model implementation and the preprocessor) are
    injected via the constructor rather than instantiated internally,
    so tests can supply lightweight fakes and so the active model
    implementation can be swapped without changing this class.
    """

    def __init__(self, model: BaseThreatModel, preprocessor: Optional[Preprocessor] = None):
        """
        Args:
            model: A BaseThreatModel implementation to train (e.g. a
                RandomForestThreatModel obtained from detector.create_model()).
            preprocessor: The Preprocessor used to encode raw feature
                dictionaries into numeric arrays. Defaults to a new
                Preprocessor() instance if not provided.
        """
        self._model = model
        self._preprocessor = preprocessor or Preprocessor()

    def load_dataset_from_csv(
        self,
        csv_path: str,
        label_column: str = "label",
        column_mapping: Optional[Dict[str, str]] = None,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load a labeled dataset from a CSV file and convert it into a
        (X, y) training matrix/label-vector pair.

        Args:
            csv_path: Path to a CSV file (not bundled with this module --
                point this at your own CICIDS2017 / CSE-CIC-IDS2018 /
                UNSW-NB15 / TON_IoT export, or any compatible dataset).
            label_column: Name of the column holding the ground-truth
                attack label. Public datasets vary widely here (e.g.
                CICIDS2017 commonly uses " Label" with a leading space,
                UNSW-NB15 uses "attack_cat"), so this is a required,
                explicit parameter rather than an assumption.
            column_mapping: Optional dict mapping this dataset's raw
                column names to Module 3's canonical FEATURE_ORDER names
                (e.g. {"Flow Duration": "flow_duration", "Tot Fwd Pkts":
                "total_packets_in_flow"}). Columns not present in the CSV
                (after mapping) are filled with 0.0, so partial/differently
                -shaped datasets can still be used, with the understanding
                that missing features reduce model quality.

        Returns:
            A tuple (X, y):
                X: numpy array of shape (n_samples, len(FEATURE_ORDER)).
                y: numpy array of shape (n_samples,) of AttackCategory
                    string values.

        Raises:
            TrainingDataError: If the file doesn't exist, can't be parsed
                as CSV, is empty, or is missing the label column.
        """
        if not os.path.isfile(csv_path):
            raise TrainingDataError(f"Dataset file not found: '{csv_path}'.")

        try:
            df = pd.read_csv(csv_path)
        except Exception as exc:
            raise TrainingDataError(f"Failed to parse CSV '{csv_path}': {exc}") from exc

        if df.empty:
            raise TrainingDataError(f"Dataset '{csv_path}' contains no rows.")

        if column_mapping:
            df = df.rename(columns=column_mapping)

        # Normalize column name whitespace (many public IDS datasets ship
        # with stray leading/trailing spaces in their headers).
        df.columns = [str(c).strip() for c in df.columns]
        label_column = label_column.strip()

        if label_column not in df.columns:
            raise TrainingDataError(
                f"Label column '{label_column}' not found in dataset columns: "
                f"{list(df.columns)}"
            )

        raw_feature_rows: List[Dict[str, float]] = []
        for _, row in df.iterrows():
            feature_row: Dict[str, float] = {}
            for field_name in FEATURE_ORDER:
                if field_name in CATEGORICAL_FEATURES:
                    feature_row[field_name] = str(row.get(field_name, "UNKNOWN"))
                else:
                    raw_value = row.get(field_name, 0.0)
                    try:
                        feature_row[field_name] = float(raw_value)
                    except (TypeError, ValueError):
                        feature_row[field_name] = 0.0
            raw_feature_rows.append(feature_row)

        X = self._preprocessor.transform_batch(raw_feature_rows)
        y = np.array([
            normalize_category_label(str(label)).value for label in df[label_column]
        ])

        logger.info("Loaded dataset '%s': %d samples, %d features.",
                    csv_path, X.shape[0], X.shape[1])
        return X, y

    def train(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Fit the injected model on the given training data.

        Args:
            X: Feature matrix of shape (n_samples, n_features).
            y: Target labels of shape (n_samples,).
        """
        self._model.fit(X, y)

    def train_test_split_and_train(
        self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2, random_state: int = 42
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Convenience method: split (X, y) into train/test sets, fit the
        model on the training split, and return all four splits so the
        caller can immediately call evaluate() on the held-out test set.

        Args:
            X: Full feature matrix.
            y: Full label vector.
            test_size: Fraction of data reserved for testing.
            random_state: Seed for reproducible splitting.

        Returns:
            (X_train, X_test, y_train, y_test)
        """
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        self.train(X_train, y_train)
        return X_train, X_test, y_train, y_test

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, object]:
        """
        Evaluate the (already trained) model against held-out test data.

        Args:
            X_test: Held-out feature matrix.
            y_test: Held-out ground-truth labels.

        Returns:
            A dictionary with accuracy, macro-averaged precision/recall/f1,
            and a full per-class classification_report string.

        Raises:
            ModelNotTrainedError: If the underlying model has not been
                trained or loaded yet.
        """
        if not self._model.is_trained:
            raise ModelNotTrainedError("Cannot evaluate: model has not been trained or loaded.")

        y_pred = self._model.predict(X_test)

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
            "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
            "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
            "classification_report": classification_report(y_test, y_pred, zero_division=0),
        }
        logger.info("Evaluation complete: accuracy=%.4f f1_macro=%.4f",
                    metrics["accuracy"], metrics["f1_macro"])
        return metrics

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Run batch prediction through the underlying model (e.g. for
        offline scoring of a dataset). For live, single-packet inference,
        use inference.InferenceEngine instead.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples,) of predicted class labels.
        """
        return self._model.predict(X)

    def save_model(self, path: str) -> None:
        """Persist the trained model to disk. See BaseThreatModel.save."""
        self._model.save(path)

    def load_model(self, path: str) -> None:
        """Load a previously trained model from disk. See BaseThreatModel.load."""
        self._model.load(path)
        
    
