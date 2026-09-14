# Intelligent IDS

Honeypot-Assisted Interpretable AI Architecture for Intelligent Network Intrusion Detection.

This repository is a final-year B.E. Computer Science (Cyber Security) project. The system will eventually collect attacker interactions from a controlled honeypot, extract behavioral features, classify activity with machine learning, explain predictions, assign risk, and display results on a security dashboard.

**Current status:** Modules 1–9 (backend, collection, features, ML detection, attack analysis, SHAP, risk assessment, monitoring dashboard, WebSocket live streaming).

The current honeypot source is a **controlled/simulated JSONL log**. Real Cowrie integration is a later step.

## Module 1 purpose

Module 1 provides a runnable FastAPI backend that can:

- Start a health-checked API server
- Store and retrieve attack/activity logs
- Validate incoming requests
- Persist data in SQLite (with a database URL that can later point to PostgreSQL)

## Module 2 purpose

Module 2 adds the data-collection pipeline:

```
Simulated honeypot JSONL
        ↓
     Log parser
        ↓
  Normalized event
        ↓
  Ingestion service
        ↓
AttackLog database
```

It can parse raw events, reject malformed records, ingest a single event through the API, import a sample log file, and skip duplicates. It does **not** classify attacks, score risk, or run machine learning.

The same normalized event format will be used later for Cowrie logs. A future Cowrie parser should emit `NormalizedEvent` objects; the ingestion service and database do not need to know the original source.

## Technologies used

- Python 3
- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic
- python-dotenv
- SQLite
- pytest
- scikit-learn
- pandas
- NumPy
- SHAP
- React / Vite / Tailwind CSS / Recharts

## Installation

Open PowerShell in the project root (`Intelligent IDS`).

### 1. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script activation, run this once, then activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 2. Install dependencies

```powershell
pip install -r backend\requirements.txt
```

### 3. Configure environment variables

Copy the example file if `backend\.env` is not already present:

```powershell
copy backend\.env.example backend\.env
```

Default settings:

- `DATABASE_URL=sqlite:///./ids.db` — SQLite file created at `backend/ids.db`
- `CORS_ORIGINS` — localhost origins for a future React frontend
- `COLLECTOR_SESSION_WINDOW_MINUTES=30` — optional; groups events from the same IP into one AttackLog

To use PostgreSQL later, change `DATABASE_URL` only. Application models do not need to be rewritten.

### 4. Start the backend

```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API is available at `http://127.0.0.1:8000`.

Swagger documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## API endpoints

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/health` | Service health check |
| POST | `/api/logs` | Create an attack/activity log |
| GET | `/api/logs` | List stored logs |
| GET | `/api/logs/{log_id}` | Get one log |
| DELETE | `/api/logs/{log_id}` | Delete one log |
| POST | `/api/collector/events` | Ingest one normalized honeypot event |
| POST | `/api/collector/import` | Import `honeypot/logs/sample_events.jsonl` (or another project log file) |
| GET | `/api/features` | Calculate behavioral feature vectors from stored events |
| POST | `/api/features/export` | Write calculated features to `ml/data/features.csv` |
| POST | `/api/detection/predict` | Classify a feature vector with the trained model |
| GET | `/api/detection/model` | Trained model registry, metrics, and feature importance |
| GET | `/api/detection/{detection_id}` | Stored detection record |
| POST | `/api/analysis/analyze` | Behavioral attack analysis from features + ML prediction |
| GET | `/api/analysis/{detection_id}` | Analyze a stored detection from its AttackLog events |
| GET | `/api/analysis/thresholds` | Heuristic analysis thresholds |
| POST | `/api/explain` | SHAP explanation of one ML prediction |
| GET | `/api/risk/thresholds` | Risk weights, caps, and level thresholds |
| POST | `/api/risk/assess` | Heuristic risk score and recommended action |
| GET | `/api/risk/{detection_id}` | Assess a stored detection from analysis + features |
| GET | `/api/dashboard/stats` | Aggregated event/classification/risk counts |
| GET | `/api/dashboard/timeline` | Daily activity and classification counts |
| GET | `/api/dashboard/attacks` | Attack-category distribution |
| GET | `/api/dashboard/risks` | Risk-level distribution |
| GET | `/api/dashboard/recent` | Recent detections with analysis and risk |
| GET | `/api/dashboard/alerts` | High/critical (or filtered) alerts |
| GET | `/api/dashboard/logs` | Filterable activity logs |
| GET | `/api/dashboard/events/{detection_id}` | Stored detection + analysis + risk + SHAP |
| GET | `/api/system/status` | Backend, database, ML artifact, collector mode, WebSocket client count |
| WS | `/ws/events` | Live security-event stream for the dashboard |

Collector endpoints store observed activity. When a trained Module 4 model is present, Module 9 runs the existing detection pipeline after ingest and broadcasts the stored result. They do not invent classifications.

## Module 2 data formats

Raw JSONL events (simulated honeypot output):

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

Normalized events contain `timestamp`, `source_ip`, `event_type`, `username`, `success`, and `command`. See `honeypot/README.md` for the parser and Cowrie migration plan.

Ingested AttackLog rows use:

- `status`: `collected`
- `risk_level`: `unscored`

Those placeholders mean “not classified yet.” Later modules will replace them.

## Module 3 — behavioral features

Module 3 calculates a **feature vector** from stored honeypot events. It does not train or predict.

See `ml/README.md` for every feature, formula, and the session-grouping rule (source IP + 30-minute window).

After events exist in the database:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/features
python -m ml.scripts.export_features
python -m ml.scripts.export_features --from-sample
```

Optional query parameters: `source_ip`, `log_id`, `window_minutes`.

## Module 4 — ML detection engine

The current honeypot data is **unlabeled**, so a production detector cannot be claimed yet. Module 4 still provides a complete training and inference pipeline.

1. Put a labeled CSV (Module 3 features + `label`) in `ml/data/raw/`, or use the development file for pipeline tests only.
2. Train (does not run when FastAPI starts):

```powershell
python -m ml.models.train --dataset ml\data\raw\development_labeled_features.csv
```

3. Predict:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/detection/predict -ContentType "application/json" -Body '{"total_events":4,"login_attempts":4,"failed_login_attempts":3,"successful_login_attempts":1,"command_count":0,"unique_command_count":0,"failed_login_ratio":0.75,"attempts_per_minute":2.5,"commands_per_minute":0,"unique_username_count":1,"unique_source_ip_count":1,"session_duration_seconds":90,"events_per_minute":2.5,"repeated_command_count":0,"suspicious_command_indicator":0}'
```

If no model artifact exists, this returns HTTP 503. See `ml/README.md` and `ml/data/README.md`.

## Module 5 — attack analysis

Attack analysis interprets Module 3 features. It does **not** replace the ML class.

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/analysis/analyze -ContentType "application/json" -Body '{"total_events":23,"login_attempts":20,"failed_login_attempts":19,"successful_login_attempts":1,"command_count":3,"unique_command_count":3,"failed_login_ratio":0.95,"attempts_per_minute":12,"commands_per_minute":1.8,"unique_username_count":2,"unique_source_ip_count":1,"session_duration_seconds":100,"events_per_minute":13.8,"repeated_command_count":0,"suspicious_command_indicator":0,"classification":"malicious","confidence_score":0.94}'
```

See `ml/analysis/README.md`.

## Module 6 — explainable AI (SHAP)

Module 6 explains **why the trained Random Forest produced a class**. It does not replace Module 4 or Module 5.

Train the Module 4 model first, then:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/explain -ContentType "application/json" -Body '{"total_events":4,"login_attempts":4,"failed_login_attempts":3,"successful_login_attempts":1,"command_count":0,"unique_command_count":0,"failed_login_ratio":0.75,"attempts_per_minute":2.5,"commands_per_minute":0,"unique_username_count":1,"unique_source_ip_count":1,"session_duration_seconds":90,"events_per_minute":2.5,"repeated_command_count":0,"suspicious_command_indicator":0}'
```

If no model artifact exists, this returns HTTP 503. SHAP values are calculated from the loaded model. They are not hard-coded.

Offline global mean |SHAP| (not used by the API):

```powershell
python -m ml.scripts.shap_summary --dataset ml\data\raw\development_labeled_features.csv
```

See `ml/explainability/README.md`.

## Module 7 — risk assessment and decision engine

Module 7 scores **how serious** a session looks and recommends ALLOW / ALERT / BLOCK. It does not change the ML class, does not assign an attack category, and does not run SHAP. BLOCK is a recommendation only.

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/risk/assess -ContentType "application/json" -Body '{"total_events":23,"login_attempts":20,"failed_login_attempts":19,"successful_login_attempts":1,"command_count":3,"unique_command_count":3,"failed_login_ratio":0.95,"attempts_per_minute":12,"commands_per_minute":1.8,"unique_username_count":2,"unique_source_ip_count":1,"session_duration_seconds":100,"events_per_minute":13.8,"repeated_command_count":0,"suspicious_command_indicator":0,"classification":"malicious","confidence_score":0.94,"attack_category":"BRUTE_FORCE","evidence_strength":"HIGH","indicators":["HIGH_FAILED_LOGIN_RATIO","HIGH_LOGIN_ATTEMPT_RATE"]}'
```

See `ml/risk/README.md`.

## Module 8 — security monitoring dashboard

The React dashboard reads aggregated FastAPI data. It does not calculate ML, SHAP, or risk.

```powershell
cd frontend
npm install
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) with the backend running. Empty databases show zeros and empty-state copy, not demo numbers.

Optional labeled demo rows (`status=demo`, no fabricated SHAP):

```powershell
python -m scripts.seed_demo_data
```

See `frontend/README.md`.

## Module 9 — real-time monitoring

The dashboard keeps REST for history and adds `WS /ws/events` for newly processed pipeline results.

```
POST /api/collector/events
        ↓
Modules 2–7 (existing services)
        ↓
Persist detection / analysis / risk
        ↓
Broadcast compact JSON
        ↓
Live security events (no page reload)
```

If the Module 4 model is not trained, the event is still stored, but the socket sends `system_status` with `reason=model_unavailable` instead of invented scores.

See `backend/realtime/README.md`.

## Testing

From the project root, with the virtual environment active:

```powershell
pytest -q
cd frontend
npm test
```

### Manual demonstration

1. Start FastAPI as shown above.
2. Send a controlled event:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/collector/events -ContentType "application/json" -Body '{"timestamp":"2026-09-14T10:30:00Z","source_ip":"192.168.1.50","event_type":"login_attempt","username":"admin","success":false,"command":null}'
```

3. Confirm it appears in the database:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/logs
```

4. Import the sample JSONL file:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/collector/import -ContentType "application/json" -Body '{}'
```

Or from the project root:

```powershell
python -m honeypot.scripts.import_logs
```

Expected import result for the sample file: 11 inserted events (or duplicates if already imported), grouped into 3 AttackLog rows by source IP.

Sending the same event twice returns `"result": "duplicate"` and does not create a second event row.

5. Calculate behavioral features:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/features
```

The sample import should produce 3 feature vectors. `192.168.1.50` should have `login_attempts = 4`, `failed_login_attempts = 3`, `successful_login_attempts = 1`, `failed_login_ratio = 0.75`, and `command_count = 3`.
