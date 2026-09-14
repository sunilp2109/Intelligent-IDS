"""Offline global SHAP summary for the trained Module 4 model.

This is not invoked by POST /api/explain. It reads an existing labeled CSV
and writes mean |SHAP| feature importance.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.explainability.shap_explainer import ExplanationUnavailableError
from ml.explainability.summary import compute_global_shap_importance


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute offline global SHAP importance for the trained Intelligent IDS model."
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="CSV with Module 3 features. Defaults to the dataset recorded in the model registry.",
    )
    parser.add_argument("--output", default=None, help="Optional JSON output path.")
    parser.add_argument(
        "--max-rows",
        type=int,
        default=200,
        help="Maximum rows to explain. Global SHAP is not run on the live API.",
    )
    args = parser.parse_args()
    try:
        result = compute_global_shap_importance(
            dataset_file=args.dataset,
            max_rows=args.max_rows,
        )
    except (ExplanationUnavailableError, FileNotFoundError, ValueError) as exc:
        print(str(exc))
        return 1
    text = json.dumps(result, indent=2)
    print(text)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
