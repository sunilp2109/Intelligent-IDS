# Behavioral feature extraction (Module 3)

Module 3 converts collected honeypot activity into **behavioral features** and a **feature vector** that a later scikit-learn model can consume.

It does **not** train a model, predict a class, score risk, or generate SHAP explanations.

```
Normalized honeypot events
        ↓
Feature extraction
        ↓
Behavioral feature vector
        ↓
Future ML detection engine
```

## Session / grouping strategy

The unit of analysis is a **session**, not a single raw log line.

Default grouping (same rule as Module 2 ingestion):

- Group by `source_ip`
- Keep events in the same session while they fall within 30 minutes of that session’s first timestamp
- Username is **not** a grouping key. It is counted as `unique_username_count`, so username cycling during brute force stays in one session

This does **not** mean one IP is always one attacker. It is a first sessionization rule. Pass `window_minutes` to `/api/features` to re-sessionize from raw events with a different window later.

## Input format

A list of normalized events:

```json
{
  "timestamp": "2026-09-14T10:30:00Z",
  "source_ip": "192.168.1.50",
  "event_type": "login_attempt",
  "username": "admin",
  "success": false,
  "command": null
}
```

Invalid timestamps or records are skipped. Empty input returns an empty result.

## Output format

Each session has:

- identifiers: `source_ip`, `source_ips`, `session_start`, `session_end`, optional `attack_log_id`
- `features`: named behavioral features
- `feature_vector`: the same values in a stable numeric order for scikit-learn

`X` for a future model is a list of `feature_vector` rows. No label is assigned in this module.

## Feature list and formulas

| Feature | Type | Formula |
| --- | --- | --- |
| `total_events` | int | Count of valid events |
| `login_attempts` | int | Count of `login_attempt` events |
| `failed_login_attempts` | int | `login_attempt` where `success` is false |
| `successful_login_attempts` | int | `login_attempt` where `success` is true |
| `command_count` | int | Command events with a non-empty command |
| `unique_command_count` | int | Distinct command strings |
| `failed_login_ratio` | float | `failed_login_attempts / login_attempts`, or `0` if there are no login attempts |
| `attempts_per_minute` | float | `login_attempts / (duration_minutes)` |
| `commands_per_minute` | float | `command_count / (duration_minutes)` |
| `unique_username_count` | int | Distinct non-empty usernames |
| `unique_source_ip_count` | int | Distinct source IPs in the session |
| `session_duration_seconds` | float | `latest_timestamp - earliest_timestamp` (0 for one event) |
| `events_per_minute` | float | `total_events / (duration_minutes)` |
| `repeated_command_count` | int | `command_count - unique_command_count` |
| `suspicious_command_indicator` | int | `1` if any command contains a documented heuristic pattern, else `0` |

Per-minute rates use a minimum duration of 1 second so a single-event session never produces `inf`.

`suspicious_command_indicator` is a **feature**, not a classification. The patterns (`wget`, `curl`, `nmap`, `/etc/passwd`, and others listed in `feature_extractor.py`) are a transparent heuristic and can be replaced later.

Login attempts with `success` omitted are counted in `login_attempts` but not as failed or successful.

## API

```
GET /api/features
GET /api/features?source_ip=192.168.1.50
GET /api/features?log_id=1
GET /api/features?window_minutes=15
POST /api/features/export
```

Values are calculated from stored `honeypot_events`. They are not hard-coded.

Features are computed dynamically. There is no separate FeatureRecord table.

## CSV generation

From the project root:

```powershell
python -m ml.scripts.export_features --from-sample
python -m ml.scripts.export_features
```

- `--from-sample` writes `ml/data/sample_features.csv` from `honeypot/logs/sample_events.jsonl`
- default export writes `ml/data/features.csv` from the database

`ml/data/features.csv` is generated output and is gitignored. `sample_features.csv` is committed as a reproducible example calculated from the sample log.

## Known limitations

- Sessionization by IP + time window is an approximation
- AttackLog rows created only through `POST /api/logs` (no honeypot events) are not included
- Suspicious-command matching is substring-based and can false-positive

## Module 4 — ML detection engine

Module 4 trains a supervised classifier on **labeled behavioral feature vectors** and serves predictions with class probabilities.

```
Feature vector
    ↓
Preprocessing (impute + scale)
    ↓
Random Forest
    ↓
classification + confidence
```

Current honeypot CSVs are **unlabeled**. The pipeline can be exercised with `ml/data/raw/development_labeled_features.csv`, which is synthetic development data. That file is not a legitimate IDS benchmark.

### Labels

| Label | Meaning |
| --- | --- |
| `normal` | Ordinary session behavior |
| `suspicious` | Unusual but not confirmed malicious behavior |
| `malicious` | Behavior consistent with hostile activity in the training labels |

Labels must come from the training CSV. The API does not invent them.

### Model

**Random Forest Classifier** is the saved model because the inputs are tabular behavioral features, trees capture non-linear combinations, class probabilities are available, and feature importances exist for later XAI. `class_weight='balanced'` is used because real IDS data is often imbalanced. Logistic Regression is a reasonable later baseline comparison; it is not trained in this module.

Training is 80/20 stratified (`random_state=42`). The test split is not used for fitting.

### Commands

Install ML libraries (already listed in `backend/requirements.txt`):

```powershell
pip install -r backend\requirements.txt
```

Build or refresh the development dataset (optional):

```powershell
python -m ml.scripts.build_development_dataset
```

Validate a labeled CSV:

```powershell
python -m ml.models.train --dataset ml\data\raw\development_labeled_features.csv --validate-only
```

Train, evaluate the hold-out split, and save artifacts:

```powershell
python -m ml.models.train --dataset ml\data\raw\development_labeled_features.csv
```

Evaluate a saved model against a labeled file (not a hold-out test if you pass the training file):

```powershell
python -m ml.evaluation.evaluate --dataset ml\data\raw\development_labeled_features.csv
```

Artifacts (gitignored):

- `ml/artifacts/intrusion_model.joblib`
- `ml/artifacts/model_registry.json`

Inference API after training:

```
POST /api/detection/predict
GET  /api/detection/model
```

If no artifact exists, the API returns HTTP 503. It does not return a fake class.

`explanation` on stored detections is always null until the XAI module.

### Limitations

- Model quality depends on labeled training data.
- The development dataset is too small and too synthetic for production IDS claims.
- Honeypot sessions are not the same as live enterprise traffic.
- Confidence is a class probability, not certainty.
- Unknown attacks can be misclassified.
- This module does not implement SHAP, risk scoring, or blocking.

