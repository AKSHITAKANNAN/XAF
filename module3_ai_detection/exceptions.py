"""
exceptions.py (Module 3)
---------------------------
Custom exception hierarchy for the AI Threat Detection Engine.

WHY THIS FILE EXISTS
Raising specific, named exceptions (instead of bare Exception/ValueError)
lets callers -- Module 3's own inference loop, or a future Module 4 that
consumes ThreatPrediction -- catch precisely the failure mode they care
about, without accidentally swallowing unrelated bugs. This is also what
makes clean, informative logging possible at every layer.

USED BY
- feature_mapper.py  (FeatureMappingError, InvalidFeatureVectorError)
- preprocessor.py    (FeatureMappingError)
- model_loader.py    (ModelLoadError, ModelSaveError)
- detector.py        (UnsupportedModelError)
- trainer.py         (TrainingDataError, ModelNotTrainedError)
- inference.py       (ModelNotLoadedError, PredictionError, InvalidFeatureVectorError)
"""


class ThreatDetectionError(Exception):
    """Base class for every exception raised by Module 3.

    Catching this single type is enough for a caller that just wants to
    know "did anything in AI detection go wrong?" without caring about the
    specific cause.
    """


class InvalidFeatureVectorError(ThreatDetectionError):
    """Raised when a FeatureVector is missing, malformed, or unusable."""


class FeatureMappingError(ThreatDetectionError):
    """Raised when a FeatureVector cannot be converted into ML-ready input."""


class UnsupportedModelError(ThreatDetectionError):
    """Raised when a requested model name is not implemented or unknown."""


class ModelNotLoadedError(ThreatDetectionError):
    """Raised when inference is attempted before a model has been loaded/trained."""


class ModelNotTrainedError(ThreatDetectionError):
    """Raised when an operation (predict/save/evaluate) requires a fitted model
    but the underlying model has not been trained yet."""


class ModelLoadError(ThreatDetectionError):
    """Raised when a persisted model file cannot be found, read, or deserialized."""


class ModelSaveError(ThreatDetectionError):
    """Raised when a model cannot be persisted to disk."""


class TrainingDataError(ThreatDetectionError):
    """Raised when a training dataset (CSV) is missing, malformed, or empty."""


class PredictionError(ThreatDetectionError):
    """Raised when the inference pipeline fails to produce a ThreatPrediction."""
