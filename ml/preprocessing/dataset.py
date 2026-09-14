from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.models.config import LABELS, RANDOM_STATE, TEST_SIZE
from ml.preprocessing.feature_schema import FEATURE_NAMES

REQUIRED_COLUMNS = [*FEATURE_NAMES, "label"]


@dataclass
class DatasetValidation:
    samples: int
    classes: dict[str, int]
    missing_values: int
    invalid_values: int
    duplicate_rows: int
    issues: list[str] = field(default_factory=list)
    dropped_invalid_label_rows: int = 0
    is_balanced: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "classes": self.classes,
            "missing_values": self.missing_values,
            "invalid_values": self.invalid_values,
            "duplicate_rows": self.duplicate_rows,
            "dropped_invalid_label_rows": self.dropped_invalid_label_rows,
            "is_balanced": self.is_balanced,
            "issues": self.issues,
        }


class DatasetValidationError(ValueError):
    pass


def load_dataset(path: str | Path) -> pd.DataFrame:
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Labeled dataset not found: {dataset_path}")
    frame = pd.read_csv(dataset_path)
    return frame


def _numeric_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    numeric = frame[list(FEATURE_NAMES)].apply(pd.to_numeric, errors="coerce")
    return numeric.replace([np.inf, -np.inf], np.nan)


def validate_dataset(frame: pd.DataFrame, *, allow_empty: bool = False) -> DatasetValidation:
    issues: list[str] = []
    missing_columns = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing_columns:
        raise DatasetValidationError(f"Dataset is missing required columns: {', '.join(missing_columns)}")

    working = frame.copy()
    if "label" not in working.columns:
        raise DatasetValidationError("Dataset is missing required column: label")

    working["label"] = working["label"].astype("string").str.strip().str.lower()
    invalid_label_mask = ~working["label"].isin(LABELS)
    dropped_invalid_labels = int(invalid_label_mask.sum())
    if dropped_invalid_labels:
        issues.append(
            f"{dropped_invalid_labels} row(s) have labels outside {list(LABELS)} and were excluded from training."
        )
        working = working.loc[~invalid_label_mask].copy()

    numeric = _numeric_feature_frame(working)
    missing_values = int(numeric.isna().sum().sum())
    raw_numeric = working[list(FEATURE_NAMES)].apply(pd.to_numeric, errors="coerce")
    invalid_values = int(np.isinf(raw_numeric.to_numpy(dtype=float, copy=True)).sum())
    duplicate_rows = int(working.duplicated(subset=[*FEATURE_NAMES, "label"]).sum())
    class_counts = {
        label: int((working["label"] == label).sum()) for label in LABELS
    }
    samples = int(len(working))

    if samples == 0 and not allow_empty:
        raise DatasetValidationError("Dataset contains no usable labeled rows.")
    if missing_values:
        issues.append(f"{missing_values} missing numeric value(s) were found. They will be imputed during preprocessing.")
    if invalid_values:
        issues.append(f"{invalid_values} infinite numeric value(s) were found. They will be treated as missing and imputed.")
    if duplicate_rows:
        issues.append(f"{duplicate_rows} duplicate labeled row(s) were found. They were kept.")

    present_counts = [count for count in class_counts.values() if count > 0]
    is_balanced = True
    if present_counts:
        max_count = max(present_counts)
        min_count = min(present_counts)
        is_balanced = (max_count / max(min_count, 1)) <= 2.0
        if not is_balanced:
            issues.append(
                "Class distribution is imbalanced. Random Forest will use class_weight='balanced'."
            )
        missing_classes = [label for label, count in class_counts.items() if count == 0]
        if missing_classes:
            issues.append(f"No training rows were found for class(es): {', '.join(missing_classes)}.")

    return DatasetValidation(
        samples=samples,
        classes=class_counts,
        missing_values=missing_values,
        invalid_values=invalid_values,
        duplicate_rows=duplicate_rows,
        issues=issues,
        dropped_invalid_label_rows=dropped_invalid_labels,
        is_balanced=is_balanced,
    )


def prepare_xy(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    working = frame.copy()
    working["label"] = working["label"].astype("string").str.strip().str.lower()
    working = working.loc[working["label"].isin(LABELS)].copy()
    features = _numeric_feature_frame(working)
    labels = working["label"]
    return features, labels


def split_data(
    features: pd.DataFrame,
    labels: pd.Series,
    *,
    test_size: float = TEST_SIZE,
    random_state: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    if labels.nunique() > 1 and labels.value_counts().min() >= 2:
        return train_test_split(
            features,
            labels,
            test_size=test_size,
            random_state=random_state,
            stratify=labels,
        )
    return train_test_split(
        features,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=None,
    )
