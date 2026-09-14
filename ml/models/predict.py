from __future__ import annotations

from typing import Any

import joblib
from sklearn.pipeline import Pipeline

from ml.models.config import artifact_dir, model_path
from ml.models.model_registry import load_registry
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.preprocessing.preprocessor import features_to_frame


class ModelNotFoundError(FileNotFoundError):
    pass


class InvalidFeatureInputError(ValueError):
    pass


def load_model_bundle(directory=None) -> dict[str, Any]:
    path = model_path(directory)
    if not path.is_file():
        raise ModelNotFoundError(
            "No trained model is available. Train one first with: python -m ml.models.train"
        )
    bundle = joblib.load(path)
    if "pipeline" not in bundle:
        raise ModelNotFoundError("The model artifact is missing a preprocessing+model pipeline.")
    return bundle


def validate_feature_payload(features: dict[str, Any]) -> dict[str, Any]:
    missing = [name for name in FEATURE_NAMES if name not in features]
    if missing:
        raise InvalidFeatureInputError(f"Missing required feature(s): {', '.join(missing)}")
    cleaned: dict[str, Any] = {}
    for name in FEATURE_NAMES:
        value = features[name]
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise InvalidFeatureInputError(f"Feature {name} must be numeric.") from exc
        if number != number:
            raise InvalidFeatureInputError(f"Feature {name} is NaN.")
        cleaned[name] = number
    return cleaned


def predict_features(features: dict[str, Any], *, directory=None) -> dict[str, Any]:
    cleaned = validate_feature_payload(features)
    bundle = load_model_bundle(directory)
    pipeline: Pipeline = bundle["pipeline"]
    frame = features_to_frame(cleaned)
    probabilities = pipeline.predict_proba(frame)[0]
    classes = list(pipeline.classes_)
    best_index = int(probabilities.argmax())
    registry = load_registry(directory or artifact_dir())
    return {
        "classification": str(classes[best_index]),
        "confidence_score": float(probabilities[best_index]),
        "class_probabilities": {
            str(label): float(score) for label, score in zip(classes, probabilities, strict=True)
        },
        "model_name": registry.model_name if registry else "random_forest",
        "model_version": registry.model_version if registry else None,
        "dataset_kind": registry.dataset_kind if registry else None,
    }
