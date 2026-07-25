"""
model_loader.py (Module 3)
-----------------------------
Generic, model-agnostic persistence helpers: serialize/deserialize any
picklable model object to/from disk.

WHY THIS FILE EXISTS
Saving and loading a model artifact is a mechanical file-system concern
that has nothing to do with what the model does (Random Forest today,
possibly XGBoost or a neural network tomorrow). Isolating it here means
every BaseThreatModel implementation in detector.py can reuse the exact
same, well-tested save/load code instead of each reimplementing
joblib/pickle handling (and its error cases) independently.

USED BY
- detector.py (RandomForestThreatModel.save() / .load() delegate here)
"""

import os

import joblib

from module3_ai_detection.exceptions import ModelLoadError, ModelSaveError
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.model_loader")


def save_model(model_object: object, path: str) -> None:
    """
    Serialize an arbitrary model object to disk using joblib.

    Args:
        model_object: Any picklable Python object (typically a fitted
            scikit-learn-compatible estimator).
        path: Destination file path. Parent directories are created
            automatically if they don't already exist.

    Raises:
        ModelSaveError: If the object cannot be serialized or written
            (e.g. permissions error, disk full, unpicklable object).
    """
    try:
        parent_dir = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent_dir, exist_ok=True)
        joblib.dump(model_object, path)
        logger.info("Model saved to %s", path)
    except Exception as exc:
        logger.error("Failed to save model to %s: %s", path, exc)
        raise ModelSaveError(f"Failed to save model to '{path}': {exc}") from exc


def load_model(path: str) -> object:
    """
    Deserialize a model object previously written by save_model().

    Args:
        path: Path to a joblib-serialized model artifact.

    Returns:
        The deserialized Python object (typically a fitted estimator).

    Raises:
        ModelLoadError: If the file does not exist, is unreadable, or is
            not a valid joblib/pickle artifact.
    """
    if not os.path.isfile(path):
        raise ModelLoadError(f"Model file not found at '{path}'.")

    try:
        model_object = joblib.load(path)
        logger.info("Model loaded from %s", path)
        return model_object
    except Exception as exc:
        logger.error("Failed to load model from %s: %s", path, exc)
        raise ModelLoadError(f"Failed to load model from '{path}': {exc}") from exc


def model_exists(path: str) -> bool:
    """
    Check whether a model artifact already exists at the given path,
    without attempting to load it.

    Args:
        path: Path to check.

    Returns:
        True if a file exists at that path, False otherwise.
    """
    return os.path.isfile(path)
