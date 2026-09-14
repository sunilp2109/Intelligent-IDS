"""Train on the labeled development CSV and persist a hold-out evaluation record.

Does not overwrite previous experiment JSON files.
Hold-out metrics come from the Module 4 train/test split (random_state=42, test_size=0.2).
They are pipeline-verification numbers, not a production IDS claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ml.evaluation.evaluate import one_vs_rest_rates
from ml.models.config import (
    DEFAULT_DEVELOPMENT_DATASET,
    LABELS,
    MODEL_NAME,
    MODEL_VERSION,
    RANDOM_STATE,
    TEST_SIZE,
)
from ml.models.train import train_and_save
from ml.preprocessing.feature_schema import FEATURE_NAMES as SCHEMA_FEATURES

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _dataset_hash(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _next_experiment_path(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    existing = [int(item.stem.split("_")[1]) for item in directory.glob("experiment_*.json") if item.stem.split("_")[1].isdigit()]
    next_id = max(existing, default=0) + 1
    return directory / f"experiment_{next_id:03d}.json"


def run_holdout_experiment(dataset: str | Path | None = None, *, output_dir: Path | None = None) -> dict[str, Any]:
    dataset_path = Path(dataset) if dataset else DEFAULT_DEVELOPMENT_DATASET
    if not dataset_path.is_file():
        return {
            "completed": False,
            "reason": f"Evaluation could not be completed because the required dataset is unavailable: {dataset_path}",
        }
    result = train_and_save(dataset_path, output_dir=output_dir)
    metrics = result["metrics"]
    security = one_vs_rest_rates(metrics, positive_class="malicious")
    record = {
        "completed": True,
        "trained_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "dataset": str(dataset_path),
        "dataset_sha256": _dataset_hash(dataset_path),
        "dataset_kind": result.get("dataset_kind"),
        "dataset_rows": result["validation"]["samples"],
        "feature_list": list(SCHEMA_FEATURES),
        "labels": list(LABELS),
        "train_test_split": {
            "test_size": TEST_SIZE,
            "random_state": RANDOM_STATE,
            "stratified": True,
        },
        "model": {
            "name": MODEL_NAME,
            "version": MODEL_VERSION,
            "parameters": {
                "n_estimators": 100,
                "max_depth": 8,
                "min_samples_leaf": 2,
                "class_weight": "balanced",
                "random_state": RANDOM_STATE,
            },
            "preprocessing": "SimpleImputer(median) + StandardScaler",
        },
        "notes": result.get("notes"),
        "holdout_metrics": metrics,
        "malicious_one_vs_rest": security,
    }
    path = _next_experiment_path(RESULTS_DIR)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    matrix_path = path.with_name(path.stem + "_confusion_matrix.csv")
    labels = metrics["confusion_matrix"]["labels"]
    matrix = metrics["confusion_matrix"]["matrix"]
    lines = ["actual\\predicted," + ",".join(labels)]
    for label, row in zip(labels, matrix, strict=True):
        lines.append(label + "," + ",".join(str(value) for value in row))
    matrix_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    record["result_file"] = str(path)
    record["confusion_matrix_csv"] = str(matrix_path)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a reproducible hold-out ML evaluation experiment.")
    parser.add_argument("--dataset", default=str(DEFAULT_DEVELOPMENT_DATASET))
    args = parser.parse_args()
    record = run_holdout_experiment(args.dataset)
    print(json.dumps(record, indent=2, default=str))
    return 0 if record.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
