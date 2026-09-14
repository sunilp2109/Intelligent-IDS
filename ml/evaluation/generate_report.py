"""Build evaluation_report.json from actual experiments. Never invents metrics."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from ml.evaluation.run_experiment import RESULTS_DIR, run_holdout_experiment
from tests.performance.benchmark_pipeline import run_benchmark
from tests.performance.timing import summarize_ms

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_JSON = PROJECT_ROOT / "ml" / "evaluation" / "evaluation_report.json"
REPORT_MD = PROJECT_ROOT / "ml" / "evaluation" / "evaluation_report.md"


def _run_pytest() -> dict:
    env = os.environ.copy()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--tb=no",
            "--cov=app",
            "--cov=ml",
            "--cov=honeypot",
            "--cov-report=term",
            f"--cov-report=json:{RESULTS_DIR / 'coverage.json'}",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    passed = failed = skipped = 0
    match = re.search(r"(\d+) passed", output)
    if match:
        passed = int(match.group(1))
    match = re.search(r"(\d+) failed", output)
    if match:
        failed = int(match.group(1))
    match = re.search(r"(\d+) skipped", output)
    if match:
        skipped = int(match.group(1))
    coverage_pct = None
    cov_file = RESULTS_DIR / "coverage.json"
    if cov_file.is_file():
        coverage_pct = json.loads(cov_file.read_text(encoding="utf-8")).get("totals", {}).get("percent_covered")
    return {
        "exit_code": proc.returncode,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "coverage_percent": coverage_pct,
        "output_tail": "\n".join(output.strip().splitlines()[-20:]),
    }


def _measure_e2e_and_websocket(iterations: int = 8) -> dict:
    from dataclasses import replace
    from datetime import timedelta

    import pandas as pd
    from fastapi.testclient import TestClient

    from app.database import Base, SessionLocal, engine
    from app.main import app
    from app.services.pipeline import process_security_event
    from ml.explainability.shap_explainer import clear_explainer_cache
    from ml.models.train import train_and_save
    from ml.scripts.build_development_dataset import build_development_rows
    from tests.support import load_fixture

    tmp = Path(tempfile.mkdtemp(prefix="ids-e2e-"))
    os.environ["ML_ARTIFACT_DIR"] = str(tmp)
    dataset = tmp / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp)
    clear_explainer_cache()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    events, _ = load_fixture("brute_force.jsonl")
    e2e_ms: list[float] = []
    with TestClient(app) as client:
        with client.websocket_connect("/ws/events") as ws:
            ws.receive_json()
            db = SessionLocal()
            try:
                for index in range(iterations):
                    event = events[index % len(events)]
                    mutated = replace(
                        event,
                        timestamp=event.timestamp.replace(microsecond=index),
                        source_ip=f"203.0.113.{80 + index}",
                    )
                    start = time.perf_counter()
                    result = process_security_event(db, mutated)
                    if result.status == "duplicate":
                        continue
                    message = {"event_type": None}
                    deadline = time.perf_counter() + 5
                    while time.perf_counter() < deadline:
                        message = ws.receive_json()
                        if message.get("event_type") == "security_event":
                            break
                    e2e_ms.append((time.perf_counter() - start) * 1000)
            finally:
                db.close()

    wall_start = time.perf_counter()
    db = SessionLocal()
    processed = 0
    try:
        events, _ = load_fixture("high_frequency.jsonl")
        for offset, event in enumerate(events):
            mutated = replace(
                event,
                timestamp=event.timestamp + timedelta(seconds=offset * 30),
                source_ip="203.0.113.70",
            )
            outcome = process_security_event(db, mutated)
            if outcome.ingest.result == "inserted":
                processed += 1
    finally:
        db.close()
    wall = time.perf_counter() - wall_start
    return {
        "end_to_end_with_xai_and_broadcast_ms": summarize_ms(e2e_ms),
        "websocket_note": (
            "WebSocket figure is client receive time after process_security_event started, "
            "so it includes pipeline processing plus local broadcast. It is not isolated network RTT."
        ),
        "websocket_delivery_included_in_e2e": True,
        "throughput": {
            "events_processed": processed,
            "seconds": round(wall, 4),
            "events_per_second": round(processed / wall, 4) if wall else None,
        },
    }


def _md_table(report: dict) -> str:
    ml = report.get("ml_metrics") or {}
    per = ml.get("per_class") or {}
    malicious = per.get("malicious") or {}
    security = report.get("malicious_one_vs_rest") or {}
    latency = report.get("latency") or {}
    tests = report.get("functional_tests") or {}

    def cell(value):
        if value is None:
            return "unavailable"
        if isinstance(value, float):
            return f"{value:.4f}"
        return str(value)

    rows = [
        ("Accuracy", cell(ml.get("accuracy"))),
        ("Precision (macro)", cell((ml.get("macro_avg") or {}).get("precision"))),
        ("Recall (macro)", cell((ml.get("macro_avg") or {}).get("recall"))),
        ("F1-score (macro)", cell((ml.get("macro_avg") or {}).get("f1_score"))),
        ("Malicious precision", cell(malicious.get("precision"))),
        ("Malicious recall", cell(malicious.get("recall"))),
        ("Malicious F1", cell(malicious.get("f1_score"))),
        ("False positive rate (malicious ovr)", cell(security.get("false_positive_rate"))),
        ("False negative rate (malicious ovr)", cell(security.get("false_negative_rate"))),
        ("Avg ML latency (ms)", cell(((latency.get("ml_prediction") or {}).get("mean_ms")))),
        ("Median ML latency (ms)", cell(((latency.get("ml_prediction") or {}).get("median_ms")))),
        ("Max ML latency (ms)", cell(((latency.get("ml_prediction") or {}).get("max_ms")))),
        ("Avg pipeline with XAI (ms)", cell(((latency.get("pipeline_with_xai") or {}).get("mean_ms")))),
        ("Avg pipeline without XAI (ms)", cell(((latency.get("pipeline_without_xai") or {}).get("mean_ms")))),
        ("Throughput (events/sec)", cell((report.get("throughput") or {}).get("events_per_second"))),
        ("Test cases passed", cell(tests.get("passed"))),
        ("Test cases failed", cell(tests.get("failed"))),
        ("Test cases skipped", cell(tests.get("skipped"))),
        ("Coverage percent", cell(tests.get("coverage_percent"))),
    ]
    lines = [
        "# Intelligent IDS evaluation report",
        "",
        f"Generated: {report.get('generated_at')}",
        "",
        report.get("dataset_note") or "",
        "",
        "| Metric | Result |",
        "| --- | --- |",
    ]
    for name, value in rows:
        lines.append(f"| {name} | {value} |")
    lines.extend(
        [
            "",
            "## Confusion matrix (hold-out test split)",
            "",
            "Rows are actual classes, columns are predicted classes (normal, suspicious, malicious).",
            "",
            "```",
            json.dumps((ml.get("confusion_matrix") or {}), indent=2),
            "```",
            "",
            "## Limitations",
            "",
            "- Metrics use the synthetic development labeled CSV unless another dataset was passed.",
            "- Hold-out accuracy on that file is pipeline verification, not a real-world IDS score.",
            "- Latencies were measured on the local development machine.",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_report(*, benchmark_iterations: int = 15) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    eval_dir = Path(tempfile.mkdtemp(prefix="ids-eval-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{(eval_dir / 'eval.db').as_posix()}"
    os.environ.setdefault("WS_HEARTBEAT_SECONDS", "0")
    experiment = run_holdout_experiment()
    benchmark = run_benchmark(iterations=benchmark_iterations, include_api=True)
    extra = _measure_e2e_and_websocket()
    pytest_stats = _run_pytest()

    ml_metrics = experiment.get("holdout_metrics") if experiment.get("completed") else None
    report = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "dataset_note": experiment.get("notes")
        or experiment.get("reason")
        or "Hold-out evaluation of the Module 4 Random Forest.",
        "experiment_file": experiment.get("result_file"),
        "ml_metrics": ml_metrics,
        "malicious_one_vs_rest": experiment.get("malicious_one_vs_rest"),
        "latency": benchmark.get("stages_ms"),
        "api_latency": benchmark.get("api_ms"),
        "end_to_end": extra.get("end_to_end_with_xai_and_broadcast_ms"),
        "websocket": {
            "note": extra.get("websocket_note"),
            "e2e_includes_broadcast_ms": extra.get("end_to_end_with_xai_and_broadcast_ms"),
        },
        "throughput": extra.get("throughput"),
        "functional_tests": pytest_stats,
        "environment_note": benchmark.get("environment_note"),
        "fault_and_security": {
            "note": "See pytest markers fault/security. Failures are listed in functional_tests.output_tail.",
        },
    }
    REPORT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    REPORT_MD.write_text(_md_table(report), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Module 10 evaluation artifacts from live runs.")
    parser.add_argument("--iterations", type=int, default=15)
    args = parser.parse_args()
    report = generate_report(benchmark_iterations=args.iterations)
    print(json.dumps({"report": str(REPORT_JSON), "markdown": str(REPORT_MD), "tests": report["functional_tests"]}, indent=2))
    return 0 if report["functional_tests"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
