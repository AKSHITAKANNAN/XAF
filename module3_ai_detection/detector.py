"""
detector.py (Module 3)
-------------------------
Defines the common interface every ML model implementation must follow,
plus the initial concrete implementation (Random Forest).

WHY THIS FILE EXISTS
The specification requires the architecture to support swapping the
underlying algorithm (XGBoost, LightGBM, CatBoost, a neural network,
Isolation Forest) without touching trainer.py or inference.py. The
Liskov Substitution / Dependency Inversion way to guarantee that is a
single abstract base class (BaseThreatModel) that both trainer.py and
inference.py depend on -- never on RandomForestThreatModel directly.

Adding a new model later means writing one new class that implements
BaseThreatModel and registering it in create_model()'s factory dict; no
other Module 3 file needs to change.

USED BY
- trainer.py    (trains/evaluates/persists whatever BaseThreatModel it's given)
- inference.py  (predicts using whatever BaseThreatModel it's given)
- run_detection.py (uses create_model() to obtain a model instance)
"""

from abc import ABC, abstractmethod
from typing import List, Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from module3_ai_detection.exceptions import ModelNotTrainedError, UnsupportedModelError
from module3_ai_detection.model_loader import save_model, load_model
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.detector")


class BaseThreatModel(ABC):
    """
    Common interface every threat-classification model must implement.

    This is the seam that makes the ML backend swappable: trainer.py and
    inference.py are written entirely against this interface, so a future
    XGBoostThreatModel, LightGBMThreatModel, CatBoostThreatModel,
    NeuralNetworkThreatModel, or IsolationForestThreatModel can be dropped
    in without any change to the surrounding pipeline.
    """

    @property
    @abstractmethod
    def model_name(self) -> str:
        """A short, stable identifier for this model implementation (e.g. "random_forest")."""
        raise NotImplementedError

    @property
    @abstractmethod
    def is_trained(self) -> bool:
        """Whether this model instance currently holds a fitted estimator."""
        raise NotImplementedError

    @property
    @abstractmethod
    def classes_(self) -> List[str]:
        """The ordered list of class labels this model was trained on."""
        raise NotImplementedError

    @abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train the underlying estimator.

        Args:
            X: Feature matrix of shape (n_samples, n_features).
            y: Target labels of shape (n_samples,) -- string class names
                (e.g. "BENIGN", "DDOS").
        """
        raise NotImplementedError

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict the most likely class for each row of X.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples,) containing predicted class labels.
        """
        raise NotImplementedError

    @abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict per-class probabilities for each row of X.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples, n_classes), column order matching
            self.classes_.
        """
        raise NotImplementedError

    @abstractmethod
    def save(self, path: str) -> None:
        """Persist the fitted estimator to disk at `path`."""
        raise NotImplementedError

    @abstractmethod
    def load(self, path: str) -> None:
        """Load a previously persisted estimator from disk at `path`."""
        raise NotImplementedError


class RandomForestThreatModel(BaseThreatModel):
    """
    Random Forest implementation of BaseThreatModel, using
    scikit-learn's RandomForestClassifier as the underlying estimator.

    This is the initial, production model per the specification. Future
    model types follow the exact same shape (see module docstring).
    """

    def __init__(self, n_estimators: int = 200, max_depth: Optional[int] = None,
                 random_state: int = 42, class_weight: Optional[str] = "balanced"):
        """
        Args:
            n_estimators: Number of trees in the forest.
            max_depth: Maximum tree depth (None = expand until pure leaves).
            random_state: Seed for reproducible training.
            class_weight: Passed straight to scikit-learn; "balanced" helps
                with the class imbalance typical of intrusion-detection
                datasets (BENIGN traffic vastly outnumbers attacks).
        """
        self._estimator = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            class_weight=class_weight,
        )
        self._is_trained = False

    @property
    def model_name(self) -> str:
        return "random_forest"

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def classes_(self) -> List[str]:
        if not self._is_trained:
            raise ModelNotTrainedError(
                "RandomForestThreatModel has not been trained or loaded yet."
            )
        return list(self._estimator.classes_)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train the Random Forest on (X, y). See BaseThreatModel.fit."""
        logger.info("Training RandomForestThreatModel on %d samples, %d features.",
                    X.shape[0], X.shape[1])
        self._estimator.fit(X, y)
        self._is_trained = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels. See BaseThreatModel.predict."""
        if not self._is_trained:
            raise ModelNotTrainedError(
                "Cannot predict: RandomForestThreatModel has not been trained or loaded yet."
            )
        return self._estimator.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict per-class probabilities. See BaseThreatModel.predict_proba."""
        if not self._is_trained:
            raise ModelNotTrainedError(
                "Cannot predict_proba: RandomForestThreatModel has not been trained or loaded yet."
            )
        return self._estimator.predict_proba(X)

    def save(self, path: str) -> None:
        """Persist the fitted RandomForestClassifier to disk. See BaseThreatModel.save."""
        if not self._is_trained:
            raise ModelNotTrainedError(
                "Cannot save: RandomForestThreatModel has not been trained yet."
            )
        save_model(self._estimator, path)

    def load(self, path: str) -> None:
        """Load a previously persisted RandomForestClassifier. See BaseThreatModel.load."""
        self._estimator = load_model(path)
        self._is_trained = True


# Registry of model factories. Adding a new model type means implementing
# a new BaseThreatModel subclass above (or in its own file) and adding one
# line here -- no other Module 3 file needs to change.
_MODEL_FACTORIES = {
    "random_forest": RandomForestThreatModel,
}

# Model names the architecture is designed to support, but which have no
# concrete implementation yet. Requesting one of these raises a clear,
# actionable error rather than a confusing ImportError deep in a missing
# third-party library.
_PLANNED_MODELS = ("xgboost", "lightgbm", "catboost", "neural_network", "isolation_forest")


def create_model(model_name: str, **kwargs) -> BaseThreatModel:
    """
    Factory function: construct a BaseThreatModel implementation by name.

    This is the single point of extension for new model types. trainer.py
    and run_detection.py should always obtain models through this
    function rather than importing a concrete class directly, so swapping
    the active model is a one-line config change (config.default_model),
    not a code change.

    Args:
        model_name: One of config.DetectionConfig.supported_models
            (e.g. "random_forest").
        **kwargs: Forwarded to the concrete model implementation's
            constructor (e.g. n_estimators for RandomForestThreatModel).

    Returns:
        An untrained BaseThreatModel instance ready for fit() or load().

    Raises:
        UnsupportedModelError: If model_name has no registered
            implementation -- either because it's misspelled, or because
            it's a planned-but-not-yet-implemented model type.
    """
    factory = _MODEL_FACTORIES.get(model_name)
    if factory is not None:
        return factory(**kwargs)

    if model_name in _PLANNED_MODELS:
        raise UnsupportedModelError(
            f"Model '{model_name}' is a supported architecture target but has "
            f"no implementation yet. Implement a BaseThreatModel subclass for "
            f"it and register it in detector.py's _MODEL_FACTORIES to enable it."
        )

    raise UnsupportedModelError(
        f"Unknown model '{model_name}'. Known models: "
        f"{list(_MODEL_FACTORIES.keys()) + list(_PLANNED_MODELS)}"
    )
