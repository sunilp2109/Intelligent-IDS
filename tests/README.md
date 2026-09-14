# Testing and evaluation (Module 10)

This folder is the measurement layer for the Intelligent IDS. It does not change detection, risk, or SHAP logic. Every metric in generated reports comes from a live run.

TEST FIXTURE JSONL files under `tests/fixtures/` are synthetic lab records. They are not production honeypot data.

## Layout

```
tests/
├── unit/            parser, features, ML, analysis, XAI, risk, data validation
├── integration/     module hand-offs, scenarios, full pipeline, faults
├── api/             HTTP endpoints, logs, security validation
├── realtime/        WebSocket connect/broadcast/cleanup
├── performance/     local timing harness (not collected as pytest tests)
├── fixtures/        controlled JSONL scenarios
├── support.py       fixture loader
└── conftest.py      isolated SQLite + TestClient
```

## Test categories

| Marker | Meaning |
| --- | --- |
| `unit` | One component |
| `integration` | Module-to-module flow |
| `api` | REST |
| `realtime` | WebSocket |
| `fault` | Missing model, bad input, DB error |
| `security` | Validation, no secrets, BLOCK is recommendation-only |
| `performance` | Optional timing scripts |

## Commands

Install testing extras (from the project root, venv active):

```powershell
pip install -r backend\requirements.txt
```

All tests:

```powershell
pytest
```

By category:

```powershell
pytest -m unit
pytest -m integration
pytest -m api
pytest -m realtime
```

Coverage (honest line coverage of `app`, `ml`, and `honeypot`):

```powershell
pytest --cov=app --cov=ml --cov=honeypot --cov-report=term-missing
```

ML hold-out evaluation (writes `ml/evaluation/results/experiment_NNN.json`, never overwrites):

```powershell
python -m ml.evaluation.run_experiment --dataset ml\data\raw\development_labeled_features.csv
```

Local pipeline benchmark:

```powershell
python tests\performance\benchmark_pipeline.py --iterations 20
```

Full evaluation report (runs experiment + timings + pytest/coverage):

```powershell
python -m ml.evaluation.generate_report --iterations 15
```

Outputs:

- `ml/evaluation/evaluation_report.json`
- `ml/evaluation/evaluation_report.md`
- `ml/evaluation/results/experiment_*.json`
- `ml/evaluation/results/experiment_*_confusion_matrix.csv`

## How to interpret ML metrics

The development CSV is **synthetic and labeled by construction**. Hold-out scores verify that the training/evaluation code works. They are not a claim about detecting real attackers.

Multiclass metrics are reported per class (`normal`, `suspicious`, `malicious`) plus macro/weighted averages.

False positive / false negative rates for **malicious** use one-vs-rest on the confusion matrix:

- FPR = FP / (FP + TN)
- FNR = FN / (TP + FN)

A false negative is a missed malicious session.

## Latency and throughput

Timings use `time.perf_counter()` on this Windows development machine. They depend on CPU, RAM, dataset, SHAP, and whether a model artifact exists. They are not production SLAs.

End-to-end WebSocket figures include pipeline processing plus local broadcast, not isolated network RTT.

## Limitations

- No cloud load test.
- No live Cowrie.
- Empty/missing model cases must fail closed (503 / `pipeline_incomplete`), never fake a class.
- Coverage is a diagnostic, not a target percentage.
