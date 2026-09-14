from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ml.models.config import MODEL_NAME, MODEL_VERSION, registry_path


@dataclass
class ModelRegistryEntry:
    model_name: str = MODEL_NAME
    model_version: str = MODEL_VERSION
    trained_at: str = ""
    feature_list: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    dataset_path: str = ""
    dataset_kind: str = "unknown"
    dataset_rows: int = 0
    class_distribution: dict[str, int] = field(default_factory=dict)
    split: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    evaluation_metrics: dict[str, Any] = field(default_factory=dict)
    feature_importance: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def save_registry(entry: ModelRegistryEntry, directory: Path | None = None) -> Path:
    if not entry.trained_at:
        entry.trained_at = datetime.now(timezone.utc).isoformat()
    path = registry_path(directory)
    path.write_text(json.dumps(entry.to_dict(), indent=2), encoding="utf-8")
    return path


def load_registry(directory: Path | None = None) -> ModelRegistryEntry | None:
    path = registry_path(directory)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return ModelRegistryEntry(**payload)
