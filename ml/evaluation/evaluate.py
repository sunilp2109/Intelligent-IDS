from __future__ import annotations

import argparse
import json
from typing import Any

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

from ml.models.config import DEFAULT_DEVELOPMENT_DATASET, LABELS
from ml.models.predict import load_model_bundle
from ml.preprocessing.dataset import load_dataset, prepare_xy


def evaluate_predictions(y_true, y_pred, *, labels: tuple[str, ...] = LABELS) -> dict[str, Any]:
    report = classification_report(
        y_true,
        y_pred,
        labels=list(labels),
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=list(labels))
    return {
        "accuracy": float(report["accuracy"]),
        "macro_avg": {
            "precision": float(report["macro avg"]["precision"]),
            "recall": float(report["macro avg"]["recall"]),
            "f1_score": float(report["macro avg"]["f1-score"]),
        },
        "weighted_avg": {
            "precision": float(report["weighted avg"]["precision"]),
            "recall": float(report["weighted avg"]["recall"]),
            "f1_score": float(report["weighted avg"]["f1-score"]),
        },
        "per_class": {
            label: {
                "precision": float(report[label]["precision"]),
                "recall": float(report[label]["recall"]),
                "f1_score": float(report[label]["f1-score"]),
                "support": int(report[label]["support"]),
            }
            for label in labels
            if label in report
        },
        "confusion_matrix": {
            "labels": list(labels),
            "matrix": matrix.astype(int).tolist(),
        },
        "averaging": {
            "macro": "unweighted mean of per-class scores",
            "weighted": "support-weighted mean of per-class scores",
        },
    }


def one_vs_rest_rates(metrics: dict[str, Any], *, positive_class: str = "malicious") -> dict[str, Any]:
    """Binary security rates from a multiclass confusion matrix.

    Positive class defaults to malicious: a false negative is a missed attack,
    a false positive is a non-malicious session labelled malicious.
    """
    labels = list(metrics["confusion_matrix"]["labels"])
    matrix = metrics["confusion_matrix"]["matrix"]
    if positive_class not in labels:
        raise ValueError(f"{positive_class} is not in the confusion-matrix labels.")
    index = labels.index(positive_class)
    true_positive = int(matrix[index][index])
    false_negative = int(sum(matrix[index][col] for col in range(len(labels)) if col != index))
    false_positive = int(sum(matrix[row][index] for row in range(len(labels)) if row != index))
    true_negative = int(
        sum(
            matrix[row][col]
            for row in range(len(labels))
            for col in range(len(labels))
            if row != index and col != index
        )
    )
    fpr_den = false_positive + true_negative
    fnr_den = true_positive + false_negative
    return {
        "positive_class": positive_class,
        "methodology": "one-vs-rest on the multiclass confusion matrix",
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "false_positive_rate": (false_positive / fpr_den) if fpr_den else None,
        "false_negative_rate": (false_negative / fnr_den) if fnr_den else None,
        "formula": {
            "false_positive_rate": "FP / (FP + TN)",
            "false_negative_rate": "FN / (TP + FN)",
        },
    }


def format_evaluation(metrics: dict[str, Any]) -> str:
    lines = [
        f"Accuracy: {metrics['accuracy']:.4f}",
        "",
        f"{'class':<12}{'precision':>12}{'recall':>12}{'f1-score':>12}",
    ]
    for label, scores in metrics["per_class"].items():
        lines.append(
            f"{label:<12}{scores['precision']:12.4f}{scores['recall']:12.4f}{scores['f1_score']:12.4f}"
        )
    lines.extend(
        [
            "",
            f"macro avg    {metrics['macro_avg']['precision']:12.4f}{metrics['macro_avg']['recall']:12.4f}{metrics['macro_avg']['f1_score']:12.4f}",
            f"weighted avg {metrics['weighted_avg']['precision']:12.4f}{metrics['weighted_avg']['recall']:12.4f}{metrics['weighted_avg']['f1_score']:12.4f}",
            "",
            "Confusion matrix rows/columns: " + ", ".join(metrics["confusion_matrix"]["labels"]),
            str(np.array(metrics["confusion_matrix"]["matrix"])),
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a saved Intelligent IDS model against a labeled CSV."
    )
    parser.add_argument("--dataset", default=str(DEFAULT_DEVELOPMENT_DATASET))
    args = parser.parse_args()
    bundle = load_model_bundle()
    features, labels = prepare_xy(load_dataset(args.dataset))
    predictions = bundle["pipeline"].predict(features)
    metrics = evaluate_predictions(labels, predictions, labels=LABELS)
    print(format_evaluation(metrics))
    print()
    print(
        "Warning: scoring the full labeled file is not a hold-out test. "
        "Use the metrics printed by python -m ml.models.train for the unseen test split."
    )
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
