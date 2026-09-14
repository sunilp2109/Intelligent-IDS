from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import shap

from ml.explainability.shap_explainer import (
    ExplanationUnavailableError,
    MISSING_MODEL_MESSAGE,
    get_explainer,
    load_pipeline_and_model,
    transform_for_model,
)
from ml.models.config import DEFAULT_DEVELOPMENT_DATASET
from ml.models.model_registry import load_registry
from ml.preprocessing.dataset import load_dataset
from ml.preprocessing.feature_schema import FEATURE_NAMES


def _dataset_path(dataset_file: str | Path | None, directory=None) -> Path:
    if dataset_file is not None:
        path = Path(dataset_file)
        if not path.is_file():
            raise FileNotFoundError(f"Dataset not found: {path}")
        return path
    registry = load_registry(directory)
    if registry and registry.dataset_path:
        trained_on = Path(registry.dataset_path)
        if trained_on.is_file():
            return trained_on
    if DEFAULT_DEVELOPMENT_DATASET.is_file():
        return DEFAULT_DEVELOPMENT_DATASET
    raise FileNotFoundError(
        "No labeled dataset is available for global SHAP summary. "
        "Pass --dataset with a CSV of Module 3 features."
    )


def compute_global_shap_importance(
    *,
    directory=None,
    dataset_file: str | Path | None = None,
    max_rows: int | None = 200,
) -> dict[str, Any]:
    """Offline mean |SHAP| over actual rows. Not used by the prediction API."""
    try:
        pipeline, model, feature_names = load_pipeline_and_model(directory)
    except FileNotFoundError as exc:
        raise ExplanationUnavailableError(MISSING_MODEL_MESSAGE) from exc
    dataset_path = _dataset_path(dataset_file, directory)
    frame = load_dataset(dataset_path)
    missing = [name for name in FEATURE_NAMES if name not in frame.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature(s): {', '.join(missing)}")
    working = frame.loc[:, list(FEATURE_NAMES)].copy()
    if max_rows is not None and len(working) > max_rows:
        working = working.iloc[: int(max_rows)]
    if working.empty:
        raise ValueError("Dataset has no rows to explain.")

    transformed_rows = []
    for _, row in working.iterrows():
        features = {name: float(row[name]) for name in FEATURE_NAMES}
        transformed_rows.append(transform_for_model(pipeline, features)[0])
    transformed = np.asarray(transformed_rows, dtype=float)
    explainer = get_explainer(directory)
    raw_values = explainer.shap_values(transformed)
    values = raw_values.values if hasattr(raw_values, "values") else raw_values
    arr = np.asarray(values, dtype=float)
    classes = [str(label) for label in model.classes_]
    n_features = len(feature_names)
    n_classes = len(classes)
    if arr.ndim == 3 and arr.shape[1] == n_features and arr.shape[2] == n_classes:
        per_class = arr
    elif isinstance(values, list) and len(values) == n_classes:
        per_class = np.stack([np.asarray(item, dtype=float) for item in values], axis=-1)
    else:
        raise ValueError(f"Unsupported SHAP summary shape: {arr.shape}")

    overall = np.mean(np.abs(per_class), axis=(0, 2))
    overall_ranked = sorted(
        (
            {"feature": name, "mean_abs_shap": float(score)}
            for name, score in zip(FEATURE_NAMES, overall, strict=True)
        ),
        key=lambda item: item["mean_abs_shap"],
        reverse=True,
    )
    by_class: dict[str, list[dict[str, float | str]]] = {}
    for index, label in enumerate(classes):
        class_mean = np.mean(np.abs(per_class[:, :, index]), axis=0)
        by_class[label] = sorted(
            (
                {"feature": name, "mean_abs_shap": float(score)}
                for name, score in zip(FEATURE_NAMES, class_mean, strict=True)
            ),
            key=lambda item: item["mean_abs_shap"],
            reverse=True,
        )
    dataset_kind = "development" if "development" in dataset_path.name.lower() else "provided"
    notes = [
        "Global SHAP is an offline summary of mean absolute contributions on the listed rows.",
        "It is not calculated on each API prediction.",
        "These values explain the trained model, not real-world causality.",
    ]
    if dataset_kind == "development":
        notes.append(
            "This summary used the synthetic development dataset and is not a production IDS result."
        )
    return {
        "shap_version": shap.__version__,
        "explainer_type": "TreeExplainer",
        "model_type": type(model).__name__,
        "dataset": str(dataset_path),
        "dataset_kind": dataset_kind,
        "rows_explained": int(len(working)),
        "feature_names": list(FEATURE_NAMES),
        "classes": classes,
        "global_feature_importance": overall_ranked,
        "feature_importance_by_class": by_class,
        "notes": notes,
    }
