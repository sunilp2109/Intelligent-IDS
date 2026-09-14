from __future__ import annotations

import os
from pathlib import Path

LABELS: tuple[str, ...] = ("normal", "suspicious", "malicious")
RANDOM_STATE = 42
TEST_SIZE = 0.2
MODEL_NAME = "random_forest"
MODEL_VERSION = "0.4.0-dev"

ML_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_DIR = ML_ROOT / "artifacts"
DEFAULT_DEVELOPMENT_DATASET = ML_ROOT / "data" / "raw" / "development_labeled_features.csv"
DATASET_TEMPLATE = ML_ROOT / "data" / "raw" / "labeled_features.template.csv"


def artifact_dir() -> Path:
    configured = os.getenv("ML_ARTIFACT_DIR")
    path = Path(configured) if configured else DEFAULT_ARTIFACT_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def model_path(directory: Path | None = None) -> Path:
    return (directory or artifact_dir()) / "intrusion_model.joblib"


def registry_path(directory: Path | None = None) -> Path:
    return (directory or artifact_dir()) / "model_registry.json"
