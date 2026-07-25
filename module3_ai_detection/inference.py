"""
inference.py (Module 3)
--------------------------
Top-level orchestrator of the AI Threat Detection Engine's live prediction
path. This is the ONLY class other code (a future Module 4, or a live
capture pipeline) needs to call directly.

WHY THIS FILE EXISTS
Mirrors Module 2's feature_extractor.py: this is the "use case" layer that
coordinates the lower-level building blocks (FeatureMapper, Preprocessor,
BaseThreatModel, utils) into the single operation the rest of the system
needs: "given a FeatureVector, give me a ThreatPrediction." It contains no
low-level arithmetic itself and no direct scikit-learn calls -- that
separation is what makes each piece independently testable.

INPUT:  module2_feature_extraction.models.FeatureVector (Module 2's output type)
OUTPUT: module3_ai_detection.models.ThreatPrediction

This module does NOT capture packets, extract features, block traffic,
explain predictions, or generate reports -- only AI-based classification,
per the Module 3 specification.

USED BY
- run_detection.py
- A future Module 4 (Smart Response / Explainability)
"""

from typing import List, Optional

import numpy as np

# NOTE: This is the one and only integration point with Module 2. Module 3
# depends on Module 2's FeatureVector type as its input contract, but does
# not import or rely on any of Module 2's internal implementation details
# (FlowBuilder, SessionManager, etc.).
from module2_feature_extraction.models import FeatureVector

from module3_ai_detection.config import DetectionConfig, DEFAULT_CONFIG
from module3_ai_detection.models import ThreatPrediction, AttackCategory
from module3_ai_detection.detector import BaseThreatModel
from module3_ai_detection.feature_mapper import FeatureMapper
from module3_ai_detection.preprocessor import Preprocessor
from module3_ai_detection.utils import (
    classify_severity, derive_threat_label, compute_risk_score, get_timestamp,
    normalize_category_label,
)
from module3_ai_detection.exceptions import (
    ModelNotLoadedError, PredictionError, InvalidFeatureVectorError,
)
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.inference")


class InferenceEngine:
    """
    Converts live FeatureVector objects (from Module 2) into ThreatPrediction
    objects, using an already-trained/loaded BaseThreatModel.

    Typical usage, wired directly onto Module 2's output:

        from module2_feature_extraction import FeatureExtractionEngine
        from module3_ai_detection.detector import create_model
        from module3_ai_detection.inference import InferenceEngine

        model = create_model("random_forest")
        model.load("trained_models/random_forest_threat_model.joblib")
        inference_engine = InferenceEngine(model=model)

        feature_engine = FeatureExtractionEngine()

        def on_packet(packet_data):
            feature_vector = feature_engine.extract(packet_data)
            threat_prediction = inference_engine.predict(feature_vector)
            print(threat_prediction)
    """

    def __init__(self, model: BaseThreatModel, config: Optional[DetectionConfig] = None,
                 feature_mapper: Optional[FeatureMapper] = None,
                 preprocessor: Optional[Preprocessor] = None):
        """
        Args:
            model: A BaseThreatModel implementation that has already been
                trained or loaded (see detector.create_model(),
                trainer.Trainer, or BaseThreatModel.load()). Injected
                rather than constructed internally, so the active model
                type/instance can be swapped without changing this class.
            config: Tunable settings (thresholds, risk weights). Defaults
                to config.DEFAULT_CONFIG.
            feature_mapper: Injected FeatureMapper. Defaults to a new
                FeatureMapper() instance.
            preprocessor: Injected Preprocessor. Defaults to a new
                Preprocessor() instance. NOTE: if a custom Preprocessor
                was used during training, the SAME instance/configuration
                must be used here, or predictions will be meaningless.
        """
        self._model = model
        self._config = config or DEFAULT_CONFIG
        self._feature_mapper = feature_mapper or FeatureMapper()
        self._preprocessor = preprocessor or Preprocessor()

    def predict(self, feature_vector: FeatureVector) -> ThreatPrediction:
        """
        Convert a single FeatureVector into a ThreatPrediction.

        Args:
            feature_vector: A FeatureVector as produced by Module 2's
                FeatureExtractionEngine.

        Returns:
            A fully populated ThreatPrediction.

        Raises:
            InvalidFeatureVectorError: If feature_vector is None or malformed.
            ModelNotLoadedError: If the injected model has not been
                trained/loaded yet.
            PredictionError: If any other step of the pipeline fails.
                Callers processing a live stream should catch this so one
                bad packet never stops detection for the rest of the stream.
        """
        if feature_vector is None:
            raise InvalidFeatureVectorError("feature_vector must not be None.")

        if not self._model.is_trained:
            raise ModelNotLoadedError(
                "InferenceEngine's model has not been trained or loaded. "
                "Call model.load(path) or train it via trainer.Trainer first."
            )

        try:
            raw_features = self._feature_mapper.map(feature_vector)
            X = self._preprocessor.transform(raw_features)

            probabilities = self._model.predict_proba(X)[0]
            class_labels = self._model.classes_

            predicted_index = int(np.argmax(probabilities))
            predicted_label_raw = class_labels[predicted_index]
            confidence_score = float(probabilities[predicted_index]) * 100.0

            attack_category = normalize_category_label(str(predicted_label_raw))
            threat_label = derive_threat_label(attack_category, confidence_score)
            severity = classify_severity(confidence_score, self._config.confidence_thresholds)
            risk_score = compute_risk_score(confidence_score, attack_category, self._config)

            prediction = ThreatPrediction(
                threat_label=threat_label,
                confidence_score=confidence_score,
                risk_score=risk_score,
                severity=severity,
                attack_category=attack_category,
                model_name=self._model.model_name,
                prediction_timestamp=get_timestamp(),
                extra={
                    "class_probabilities": {
                        str(label): float(prob)
                        for label, prob in zip(class_labels, probabilities)
                    },
                    "flow_id": feature_vector.flow_id,
                },
            )

            logger.debug("Predicted %s", prediction)
            return prediction

        except (ModelNotLoadedError, InvalidFeatureVectorError):
            raise
        except Exception as exc:
            logger.error("Failed to run inference on FeatureVector: %s", exc)
            raise PredictionError(str(exc)) from exc

    def predict_batch(self, feature_vectors: List[FeatureVector]) -> List[ThreatPrediction]:
        """
        Convert a list of FeatureVector objects into ThreatPredictions,
        skipping (and logging) any individual vector that fails inference
        rather than aborting the whole batch.

        Args:
            feature_vectors: A list of FeatureVector objects, e.g. produced
                by Module 2's FeatureExtractionEngine.extract_batch().

        Returns:
            A list of successfully produced ThreatPrediction objects (may
            be shorter than the input list if some inputs were unusable).
        """
        results: List[ThreatPrediction] = []
        for feature_vector in feature_vectors:
            try:
                results.append(self.predict(feature_vector))
            except (InvalidFeatureVectorError, PredictionError) as exc:
                logger.warning("Skipping FeatureVector during batch inference: %s", exc)
        return results
