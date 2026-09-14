"""Local pipeline timing harness. Results depend on this machine and are not production SLAs."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from tests.performance.timing import summarize_ms  # noqa: E402


def _brute_features() -> dict:
    from ml.preprocessing.feature_extractor import extract_features
    from tests.support import load_fixture

    events, _failures = load_fixture("brute_force.jsonl")
    return extract_features([event.to_dict() for event in events])


def _train(tmp_dir: Path) -> Path:
    import pandas as pd

    from ml.models.train import train_and_save
    from ml.scripts.build_development_dataset import build_development_rows

    dataset = tmp_dir / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_dir)
    return tmp_dir


def run_benchmark(*, iterations: int = 20, include_api: bool = True) -> dict:
    import os
    import tempfile

    from ml.analysis.analyzer import analyze_activity
    from ml.explainability.shap_explainer import clear_explainer_cache, explain_features
    from ml.models.predict import predict_features
    from ml.preprocessing.feature_extractor import extract_features
    from ml.risk.engine import assess_risk
    from tests.support import load_fixture

    events, _ = load_fixture("brute_force.jsonl")
    payloads = [event.to_dict() for event in events]
    tmp = Path(tempfile.mkdtemp(prefix="ids-bench-"))
    model_dir = _train(tmp)
    os.environ["ML_ARTIFACT_DIR"] = str(model_dir)
    clear_explainer_cache()
    features = extract_features(payloads)
    predict_features(features, directory=model_dir)  # warmup

    feature_ms: list[float] = []
    predict_ms: list[float] = []
    analysis_ms: list[float] = []
    shap_ms: list[float] = []
    risk_ms: list[float] = []
    without_xai_ms: list[float] = []
    with_xai_ms: list[float] = []

    for _ in range(max(1, iterations)):
        start = time.perf_counter()
        extracted = extract_features(payloads)
        feature_ms.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        prediction = predict_features(extracted, directory=model_dir)
        predict_ms.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        analysis = analyze_activity(
            extracted,
            {"classification": prediction["classification"], "confidence_score": prediction["confidence_score"]},
        )
        analysis_ms.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        explain_features(extracted, directory=model_dir)
        shap_ms.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        assess_risk(
            classification=prediction["classification"],
            confidence_score=prediction["confidence_score"],
            attack_category=analysis["attack_category"],
            evidence_strength=analysis["evidence_strength"],
            features=extracted,
            indicators=analysis["indicators"],
        )
        risk_ms.append((time.perf_counter() - start) * 1000)

        without_xai_ms.append(feature_ms[-1] + predict_ms[-1] + analysis_ms[-1] + risk_ms[-1])
        with_xai_ms.append(without_xai_ms[-1] + shap_ms[-1])

    api_times: dict[str, list[float]] = {}
    if include_api:
        os.environ["DATABASE_URL"] = f"sqlite:///{(tmp / 'bench.db').as_posix()}"
        os.environ.setdefault("WS_HEARTBEAT_SECONDS", "0")
        from fastapi.testclient import TestClient

        from app.database import Base, engine
        from app.main import app

        Base.metadata.create_all(bind=engine)
        payload = {**features, "log_id": None}
        explain_payload = dict(payload)
        risk_payload = {
            **features,
            "classification": "malicious",
            "confidence_score": 0.94,
            "attack_category": "BRUTE_FORCE",
            "evidence_strength": "HIGH",
            "indicators": ["HIGH_FAILED_LOGIN_RATIO"],
        }
        with TestClient(app) as client:
            for path, method, body in (
                ("/api/logs", "GET", None),
                ("/api/dashboard/stats", "GET", None),
                ("/api/detection/predict", "POST", payload),
                ("/api/explain", "POST", explain_payload),
                ("/api/risk/assess", "POST", risk_payload),
            ):
                samples: list[float] = []
                for _ in range(max(1, iterations)):
                    start = time.perf_counter()
                    if method == "GET":
                        response = client.get(path)
                    else:
                        response = client.post(path, json=body)
                    samples.append((time.perf_counter() - start) * 1000)
                    if response.status_code >= 500:
                        raise RuntimeError(f"{path} returned {response.status_code}: {response.text}")
                api_times[f"{method} {path}"] = samples

    result = {
        "iterations": iterations,
        "environment_note": (
            "Local development timings on the machine that ran this script. "
            "They are not production benchmarks."
        ),
        "stages_ms": {
            "feature_extraction": summarize_ms(feature_ms),
            "ml_prediction": summarize_ms(predict_ms),
            "attack_analysis": summarize_ms(analysis_ms),
            "shap_explanation": summarize_ms(shap_ms),
            "risk_assessment": summarize_ms(risk_ms),
            "pipeline_without_xai": summarize_ms(without_xai_ms),
            "pipeline_with_xai": summarize_ms(with_xai_ms),
        },
        "api_ms": {name: summarize_ms(values) for name, values in api_times.items()},
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure local Intelligent IDS pipeline timings.")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--skip-api", action="store_true")
    args = parser.parse_args()
    report = run_benchmark(iterations=args.iterations, include_api=not args.skip_api)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
