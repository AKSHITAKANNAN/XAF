"""
preprocessor.py (Module 3)
-----------------------------
Converts raw, mixed-type feature dictionaries (produced by
feature_mapper.py) into pure-numeric arrays that a scikit-learn-style
model can consume.

WHY THIS FILE EXISTS
feature_mapper.py knows WHICH fields matter; this file knows HOW to turn
those fields -- some numeric, some categorical strings -- into a flat
vector of floats. Separating "what" from "how" means the encoding scheme
(fixed vocabularies today; could become one-hot encoding, embeddings, or
a fitted scikit-learn ColumnTransformer tomorrow) can change without
touching feature selection logic, and vice versa.

The categorical vocabularies defined here are the SINGLE SOURCE OF TRUTH
for encoding both at training time (trainer.py) and inference time
(inference.py). Using one shared Preprocessor instance for both prevents
the classic ML bug where training and inference encode categories
differently.

USED BY
- trainer.py     (transform_batch, to build the training matrix from a CSV)
- inference.py   (transform, to build a single-row prediction input)
"""

from typing import Any, Dict, List

import numpy as np

from module3_ai_detection.feature_mapper import (
    NUMERIC_FEATURES, CATEGORICAL_FEATURES, FEATURE_ORDER,
)
from module3_ai_detection.exceptions import FeatureMappingError
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.preprocessor")


class Preprocessor:
    """
    Encodes raw feature dictionaries into fixed-order numeric numpy arrays.

    Fixed, hand-declared vocabularies (rather than a fitted LabelEncoder)
    are used for the small, closed-set categorical fields Module 2
    guarantees (protocol, direction, connection_state). This keeps
    encoding deterministic and trivially reproducible between training
    and inference without needing to persist a separate encoder artifact
    alongside the model file.
    """

    # Fixed vocabularies for every categorical field this module encodes.
    # Any value not found here maps to the vocabulary's own "UNKNOWN" slot,
    # so an unexpected/malformed category never raises -- it just becomes
    # a distinct, valid numeric code the model can still learn from.
    PROTOCOL_VOCAB: Dict[str, int] = {
        "TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3, "UNKNOWN": 4,
    }
    DIRECTION_VOCAB: Dict[str, int] = {
        "INBOUND": 0, "OUTBOUND": 1, "INTERNAL": 2, "UNKNOWN": 3,
    }
    CONNECTION_STATE_VOCAB: Dict[str, int] = {
        "NEW": 0, "ESTABLISHED": 1, "CLOSING": 2, "CLOSED": 3,
        "STATELESS": 4, "UNKNOWN": 5,
    }

    _VOCABS_BY_FIELD: Dict[str, Dict[str, int]] = {
        "protocol": PROTOCOL_VOCAB,
        "direction": DIRECTION_VOCAB,
        "connection_state": CONNECTION_STATE_VOCAB,
    }

    def _encode_categorical(self, field_name: str, raw_value: str) -> float:
        """
        Encode a single categorical value using its field's fixed vocabulary.

        Args:
            field_name: One of CATEGORICAL_FEATURES.
            raw_value: The raw string value to encode.

        Returns:
            The vocabulary's numeric code for raw_value, or the vocabulary's
            "UNKNOWN" code if raw_value is not recognized.
        """
        vocab = self._VOCABS_BY_FIELD[field_name]
        code = vocab.get(str(raw_value).upper(), vocab.get("UNKNOWN", -1))
        return float(code)

    def transform(self, raw_features: Dict[str, Any]) -> np.ndarray:
        """
        Convert one raw feature dictionary into a single-row numeric array.

        Args:
            raw_features: Dictionary produced by FeatureMapper.map(), keyed
                by FEATURE_ORDER.

        Returns:
            A numpy array of shape (1, len(FEATURE_ORDER)) and dtype float64,
            ready to pass to a scikit-learn model's predict()/predict_proba().

        Raises:
            FeatureMappingError: If a required key is missing from
                raw_features (indicates feature_mapper.py and
                preprocessor.py have drifted out of sync).
        """
        try:
            row: List[float] = []
            for field_name in FEATURE_ORDER:
                value = raw_features[field_name]
                if field_name in CATEGORICAL_FEATURES:
                    row.append(self._encode_categorical(field_name, value))
                else:
                    row.append(float(value))

            return np.array([row], dtype=np.float64)

        except KeyError as exc:
            logger.error("raw_features missing expected key: %s", exc)
            raise FeatureMappingError(
                f"raw_features is missing expected key: {exc}"
            ) from exc

    def transform_batch(self, raw_features_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Convert a list of raw feature dictionaries into a full training/
        evaluation matrix.

        Args:
            raw_features_list: A list of dictionaries, each as produced by
                FeatureMapper.map() or trainer.py's CSV row parsing.

        Returns:
            A numpy array of shape (n_samples, len(FEATURE_ORDER)).

        Raises:
            FeatureMappingError: If the list is empty, or if any row is
                missing an expected key.
        """
        if not raw_features_list:
            raise FeatureMappingError("raw_features_list must not be empty.")

        rows = [self.transform(row)[0] for row in raw_features_list]
        return np.array(rows, dtype=np.float64)

    @property
    def feature_names(self) -> List[str]:
        """The canonical, ordered list of feature column names."""
        return list(FEATURE_ORDER)
