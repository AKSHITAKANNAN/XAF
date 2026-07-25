"""
feature_mapper.py (Module 3)
-------------------------------
Selects and extracts the specific FeatureVector fields the ML model was
trained on, in a fixed, well-known order.

WHY THIS FILE EXISTS
This is the ONE place that knows "which fields of Module 2's FeatureVector
matter to the model, and what their raw values are." Keeping this separate
from preprocessor.py (which knows "how do we turn those raw values into
numbers a model can consume") follows the Single Responsibility Principle:
if the model needs a new feature later, this file changes; if the encoding
scheme changes, preprocessor.py changes -- never both at once for the
same reason.

This file has exactly one integration point with Module 2: it imports the
FeatureVector type for type-hinting purposes only. It does not import or
depend on any of Module 2's internal classes (FlowBuilder, SessionManager,
etc.), keeping the coupling to the smallest possible surface.

USED BY
- preprocessor.py  (consumes the dict this module produces)
- trainer.py       (uses FEATURE_ORDER / CATEGORICAL_FEATURES as the
                     canonical column layout when reading training CSVs)
"""

from typing import Any, Dict

from module2_feature_extraction.models import FeatureVector

from module3_ai_detection.exceptions import InvalidFeatureVectorError
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.feature_mapper")


# Numeric FeatureVector fields used as direct model inputs.
NUMERIC_FEATURES = (
    "packet_length",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "payload_size",
    "avg_packet_size",
    "total_packets_in_flow",
    "total_bytes",
    "inter_arrival_time",
    "ttl",
    "window_size",
    "avg_flow_time",
)

# Categorical FeatureVector fields that require encoding before they can
# be fed to the model (handled by preprocessor.py).
CATEGORICAL_FEATURES = (
    "protocol",
    "direction",
    "connection_state",
)

# The single, canonical column order used everywhere in Module 3: model
# training (trainer.py), preprocessing (preprocessor.py), and inference
# (inference.py). Defining it once here prevents column-order mismatches
# between training and inference, which is one of the most common (and
# hardest to debug) bugs in ML pipelines.
FEATURE_ORDER = NUMERIC_FEATURES + CATEGORICAL_FEATURES


class FeatureMapper:
    """
    Converts a single FeatureVector into a raw, ML-oriented dictionary.

    This class holds no state; it exists as a class (rather than a bare
    function) purely so it can be swapped out or subclassed later --
    e.g. a future FeatureMapper variant that selects a different subset
    of fields for a different model architecture, injected via
    inference.py's constructor instead of hard-coded.
    """

    def map(self, feature_vector: FeatureVector) -> Dict[str, Any]:
        """
        Extract the model-relevant fields from a FeatureVector.

        Args:
            feature_vector: A FeatureVector produced by Module 2's
                FeatureExtractionEngine.

        Returns:
            A dictionary keyed by FEATURE_ORDER, with:
                - numeric fields as floats (None -> 0.0)
                - categorical fields as their raw string value (enum -> .value)

        Raises:
            InvalidFeatureVectorError: If feature_vector is None or is
                missing an expected attribute (e.g. a caller passed an
                unrelated object by mistake).
        """
        if feature_vector is None:
            raise InvalidFeatureVectorError("feature_vector must not be None.")

        try:
            raw: Dict[str, Any] = {}

            for field_name in NUMERIC_FEATURES:
                value = getattr(feature_vector, field_name)
                raw[field_name] = float(value) if value is not None else 0.0

            for field_name in CATEGORICAL_FEATURES:
                value = getattr(feature_vector, field_name)
                # Module 2's direction/connection_state are enums; protocol
                # is a plain string. Normalize both to a plain string here.
                raw[field_name] = value.value if hasattr(value, "value") else str(value)

            return raw

        except AttributeError as exc:
            logger.error("FeatureVector missing expected attribute: %s", exc)
            raise InvalidFeatureVectorError(
                f"feature_vector is missing an expected attribute: {exc}"
            ) from exc
