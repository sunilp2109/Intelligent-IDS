from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from ml.evaluation.evaluate import evaluate_predictions, format_evaluation
from ml.models.config import (
    DEFAULT_DEVELOPMENT_DATASET,
    LABELS,
    MODEL_NAME,
    MODEL_VERSION,
    RANDOM_STATE,
    TEST_SIZE,
    artifact_dir,
    model_path,
)
from ml.models.model_registry import ModelRegistryEntry, save_registry
from ml.preprocessing.dataset import (
    DatasetValidationError,
    load_dataset,
    prepare_xy,
    split_data,
    validate_dataset,
)
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.preprocessing.preprocessor import build_preprocessor

logger = logging.getLogger("intelligent_ids.ml")

DEVELOPMENT_NOTE = (
    "Trained on a development/test labeled dataset. These metrics are for pipeline "
    "verification only and are not a production IDS evaluation."
)


def _is_development_dataset(path: Path) -> bool:
    return "development" in path.name.lower()


def build_model() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=1,
    )


def feature_importance(pipeline: Pipeline) -> list[dict[str, Any]]:
    classifier = pipeline.named_steps["model"]
    importances = getattr(classifier, "feature_importances_", None)
    if importances is None:
        return []
    ranked = sorted(
        (
            {"feature": name, "importance": float(score)}
            for name, score in zip(FEATURE_NAMES, importances, strict=True)
        ),
        key=lambda item: item["importance"],
        reverse=True,
    )
    return ranked


def train_and_save(
    dataset_file: str | Path,
    *,
    output_dir: Path | None = None,
    validate_only: bool = False,
) -> dict[str, Any]:
    dataset_path = Path(dataset_file)
    frame = load_dataset(dataset_path)
    report = validate_dataset(frame)
    logger.info("Dataset validation %s", json.dumps(report.to_dict()))
    if validate_only:
        return {"validation": report.to_dict(), "trained": False}

    features, labels = prepare_xy(frame)
    x_train, x_test, y_train, y_test = split_data(features, labels)
    overlap = set(x_train.index).intersection(x_test.index)
    if overlap:
        raise RuntimeError("Train/test split leaked rows.")

    pipeline = Pipeline(
        steps=[
            ("preprocess", build_preprocessor()),
            ("model", build_model()),
        ]
    )
    pipeline.fit(x_train, y_train)
    y_pred = pipeline.predict(x_test)
    metrics = evaluate_predictions(y_test, y_pred, labels=LABELS)
    logger.info("Hold-out evaluation\n%s", format_evaluation(metrics))

    directory = output_dir or artifact_dir()
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": pipeline,
            "feature_names": list(FEATURE_NAMES),
            "labels": list(pipeline.named_steps["model"].classes_),
        },
        model_path(directory),
    )

    dataset_kind = "development" if _is_development_dataset(dataset_path) else "external"
    notes = DEVELOPMENT_NOTE if dataset_kind == "development" else "Trained on the provided labeled dataset."
    entry = ModelRegistryEntry(
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_list=list(FEATURE_NAMES),
        labels=list(LABELS),
        dataset_path=str(dataset_path),
        dataset_kind=dataset_kind,
        dataset_rows=report.samples,
        class_distribution=report.classes,
        split={
            "test_size": TEST_SIZE,
            "random_state": RANDOM_STATE,
            "stratified": True,
            "train_rows": int(len(x_train)),
            "test_rows": int(len(x_test)),
        },
        parameters={
            "n_estimators": 100,
            "max_depth": 8,
            "min_samples_leaf": 2,
            "class_weight": "balanced",
            "random_state": RANDOM_STATE,
        },
        evaluation_metrics=metrics,
        feature_importance=feature_importance(pipeline),
        notes=notes,
    )
    save_registry(entry, directory)
    return {
        "validation": report.to_dict(),
        "trained": True,
        "model_path": str(model_path(directory)),
        "metrics": metrics,
        "dataset_kind": dataset_kind,
        "notes": notes,
        "feature_importance": entry.feature_importance,
    }


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    parser = argparse.ArgumentParser(description="Train the Intelligent IDS Random Forest detector.")
    parser.add_argument(
        "--dataset",
        default=str(DEFAULT_DEVELOPMENT_DATASET),
        help="CSV with Module 3 features plus a label column.",
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    try:
        result = train_and_save(
            args.dataset,
            output_dir=Path(args.output_dir) if args.output_dir else None,
            validate_only=args.validate_only,
        )
    except (FileNotFoundError, DatasetValidationError) as exc:
        print(str(exc))
        return 1
    print(json.dumps(result, indent=2, default=str))
    if result.get("dataset_kind") == "development":
        print(DEVELOPMENT_NOTE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
