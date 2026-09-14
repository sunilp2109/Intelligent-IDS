from __future__ import annotations

from typing import Any

import numpy as np
import shap
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

from ml.explainability.explanation_formatter import (
    DEFAULT_TOP_FEATURES,
    contribution_direction,
    format_explanation,
)
from ml.models.config import model_path
from ml.models.predict import (
    InvalidFeatureInputError,
    load_model_bundle,
    predict_features,
    validate_feature_payload,
)
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.preprocessing.preprocessor import features_to_frame

TREE_CLASSIFIERS = (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    DecisionTreeClassifier,
)

MISSING_MODEL_MESSAGE = (
    "Trained model not found. Train the Module 4 model before generating explanations."
)

_EXPLAINER_CACHE: dict[tuple[str, float], shap.TreeExplainer] = {}


class ExplanationUnavailableError(FileNotFoundError):
    pass


class ExplanationError(RuntimeError):
    pass


def clear_explainer_cache() -> None:
    _EXPLAINER_CACHE.clear()


def _require_tree_model(model: Any) -> Any:
    if not isinstance(model, TREE_CLASSIFIERS):
        raise ExplanationError(
            f"Unsupported model type {type(model).__name__}. "
            "Module 6 uses SHAP TreeExplainer for the Module 4 Random Forest."
        )
    return model


def create_explainer(model: Any) -> shap.TreeExplainer:
    """Create a SHAP explainer that matches the loaded Module 4 model."""
    return shap.TreeExplainer(_require_tree_model(model))


def load_pipeline_and_model(directory=None) -> tuple[Pipeline, Any, list[str]]:
    path = model_path(directory)
    if not path.is_file():
        raise ExplanationUnavailableError(MISSING_MODEL_MESSAGE)
    try:
        bundle = load_model_bundle(directory)
    except FileNotFoundError as exc:
        raise ExplanationUnavailableError(MISSING_MODEL_MESSAGE) from exc
    pipeline = bundle["pipeline"]
    if not isinstance(pipeline, Pipeline) or "model" not in pipeline.named_steps:
        raise ExplanationError("The trained artifact does not contain a preprocessing+model pipeline.")
    model = _require_tree_model(pipeline.named_steps["model"])
    names = list(bundle.get("feature_names") or FEATURE_NAMES)
    if names != list(FEATURE_NAMES):
        raise ExplanationError(
            "The trained model feature names do not match the Module 3 feature schema."
        )
    return pipeline, model, names


def get_explainer(directory=None) -> shap.TreeExplainer:
    path = model_path(directory)
    if not path.is_file():
        raise ExplanationUnavailableError(MISSING_MODEL_MESSAGE)
    cache_key = (str(path.resolve()), path.stat().st_mtime)
    cached = _EXPLAINER_CACHE.get(cache_key)
    if cached is not None:
        return cached
    _pipeline, model, _names = load_pipeline_and_model(directory)
    explainer = create_explainer(model)
    _EXPLAINER_CACHE[cache_key] = explainer
    return explainer


def transform_for_model(pipeline: Pipeline, features: dict[str, Any]) -> np.ndarray:
    """Apply the same preprocessing used during Module 4 prediction."""
    frame = features_to_frame(features)
    if "preprocess" in pipeline.named_steps:
        transformed = pipeline.named_steps["preprocess"].transform(frame)
    else:
        transformed = pipeline[:-1].transform(frame)
    return np.asarray(transformed, dtype=float)


def _extract_class_shap(
    raw: Any,
    *,
    class_index: int,
    n_features: int,
    n_classes: int,
) -> np.ndarray:
    values = raw.values if hasattr(raw, "values") else raw
    if isinstance(values, list):
        if class_index >= len(values):
            raise ExplanationError("SHAP returned fewer class arrays than the model has classes.")
        arr = np.asarray(values[class_index], dtype=float)
        if arr.ndim == 2:
            return arr[0]
        if arr.ndim == 1 and arr.shape[0] == n_features:
            return arr
        raise ExplanationError(f"Unsupported SHAP list-item shape: {arr.shape}")

    arr = np.asarray(values, dtype=float)
    if arr.ndim == 3:
        if arr.shape[1] == n_features and arr.shape[2] == n_classes:
            return arr[0, :, class_index]
        if arr.shape[1] == n_classes and arr.shape[2] == n_features:
            return arr[0, class_index, :]
        if arr.shape[0] == n_classes and arr.shape[2] == n_features:
            return arr[class_index, 0, :]
        raise ExplanationError(f"Unsupported SHAP 3D shape: {arr.shape}")
    if arr.ndim == 2:
        if arr.shape == (1, n_features):
            return arr[0]
        if arr.shape == (n_features, n_classes):
            return arr[:, class_index]
        if arr.shape[0] == 1 and arr.shape[1] == n_classes:
            raise ExplanationError(f"Unsupported SHAP 2D shape: {arr.shape}")
        if arr.shape[1] == n_features:
            return arr[0]
        raise ExplanationError(f"Unsupported SHAP 2D shape: {arr.shape}")
    if arr.ndim == 1 and arr.shape[0] == n_features:
        return arr
    raise ExplanationError(f"Unsupported SHAP output shape: {arr.shape}")


def _extract_base_value(raw_expected: Any, *, class_index: int, n_classes: int) -> float:
    arr = np.asarray(raw_expected, dtype=float)
    if arr.ndim == 0 or arr.size == 1:
        return float(arr.reshape(-1)[0])
    if arr.ndim == 2 and arr.shape[1] == n_classes:
        return float(arr[0, class_index])
    flat = arr.reshape(-1)
    if class_index < flat.size:
        return float(flat[class_index])
    raise ExplanationError(f"Unsupported SHAP expected_value shape: {arr.shape}")


def _base_values_by_class(raw_expected: Any, classes: list[str]) -> dict[str, float]:
    arr = np.asarray(raw_expected, dtype=float).reshape(-1)
    if arr.size == 1:
        return {label: float(arr[0]) for label in classes}
    return {
        label: float(arr[index]) if index < arr.size else float("nan")
        for index, label in enumerate(classes)
    }


def compute_shap_values(
    features: dict[str, Any],
    *,
    directory=None,
) -> dict[str, Any]:
    pipeline, model, feature_names = load_pipeline_and_model(directory)
    transformed = transform_for_model(pipeline, features)
    explainer = get_explainer(directory)
    classes = [str(label) for label in model.classes_]
    try:
        raw_values = explainer.shap_values(transformed)
    except Exception as exc:  # pragma: no cover - library failure path
        raise ExplanationError("SHAP explanation failed.") from exc
    expected = getattr(raw_values, "base_values", None)
    if expected is None:
        expected = explainer.expected_value
    return {
        "raw_values": raw_values,
        "expected": expected,
        "feature_names": feature_names,
        "classes": classes,
        "model_type": type(model).__name__,
        "n_features": len(feature_names),
        "n_classes": len(classes),
    }


def explain_features(
    features: dict[str, Any],
    *,
    directory=None,
    top_n: int = DEFAULT_TOP_FEATURES,
    prediction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Explain one Module 4 prediction. Does not train a model or score risk."""
    cleaned = validate_feature_payload(features)
    if prediction is None:
        try:
            prediction = predict_features(cleaned, directory=directory)
        except FileNotFoundError as exc:
            raise ExplanationUnavailableError(MISSING_MODEL_MESSAGE) from exc
    explained_class = str(prediction["classification"])
    shap_payload = compute_shap_values(cleaned, directory=directory)
    classes = shap_payload["classes"]
    if explained_class not in classes:
        raise ExplanationError(
            f"Predicted class {explained_class} is not in the trained model classes."
        )
    class_index = classes.index(explained_class)
    class_shap = _extract_class_shap(
        shap_payload["raw_values"],
        class_index=class_index,
        n_features=shap_payload["n_features"],
        n_classes=shap_payload["n_classes"],
    )
    if class_shap.shape[0] != len(FEATURE_NAMES):
        raise ExplanationError("SHAP returned a different number of features than the model uses.")
    base_value = _extract_base_value(
        shap_payload["expected"],
        class_index=class_index,
        n_classes=shap_payload["n_classes"],
    )
    contributions = []
    for name, shap_value in zip(FEATURE_NAMES, class_shap, strict=True):
        numeric = float(shap_value)
        contributions.append(
            {
                "feature": name,
                "value": float(cleaned[name]),
                "shap_value": numeric,
                "absolute_shap_value": abs(numeric),
                "direction": contribution_direction(numeric),
            }
        )
    explanation = format_explanation(
        classification=explained_class,
        confidence_score=float(prediction["confidence_score"]),
        explained_class=explained_class,
        base_value=base_value,
        model_output=float(prediction["confidence_score"]),
        contributions=contributions,
        top_n=top_n,
        shap_version=shap.__version__,
        explainer_type="TreeExplainer",
        model_type=shap_payload["model_type"],
        base_values_by_class=_base_values_by_class(shap_payload["expected"], classes),
    )
    result = dict(prediction)
    result["explanation"] = explanation
    return result


# Re-export so API validation can use the same feature error type.
__all__ = [
    "DEFAULT_TOP_FEATURES",
    "ExplanationError",
    "ExplanationUnavailableError",
    "InvalidFeatureInputError",
    "MISSING_MODEL_MESSAGE",
    "clear_explainer_cache",
    "compute_shap_values",
    "create_explainer",
    "explain_features",
    "get_explainer",
    "load_pipeline_and_model",
    "transform_for_model",
]
