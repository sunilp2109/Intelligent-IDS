# Intelligent IDS

Honeypot-Assisted Interpretable AI Architecture for Intelligent Network Intrusion Detection.

This repository is a final-year B.E. Computer Science (Cyber Security) project. The system will eventually collect attacker interactions from a controlled honeypot, extract behavioral features, classify activity with machine learning, explain predictions, assign risk, and display results on a security dashboard.

**Current status:** Module 1 only — project foundation and backend API.

## Module 1 purpose

Module 1 provides a runnable FastAPI backend that can:

- Start a health-checked API server
- Store and retrieve attack/activity logs
- Validate incoming requests
- Persist data in SQLite (with a database URL that can later point to PostgreSQL)

This module does **not** include honeypot capture, machine learning, SHAP/XAI, attack classification, the risk engine, the dashboard, or real-time monitoring.

## Technologies used (Module 1)

- Python 3
- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic
- python-dotenv
- SQLite

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

Default Module 1 settings:

- `DATABASE_URL=sqlite:///./ids.db` — SQLite file created at `backend/ids.db`
- `CORS_ORIGINS` — localhost origins for a future React frontend

To use PostgreSQL later, change `DATABASE_URL` only. Application models do not need to be rewritten.

### 4. Start the backend

```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API is available at `http://127.0.0.1:8000`.

Swagger documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## API endpoints (Module 1)

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/health` | Service health check |
| POST | `/api/logs` | Create an attack/activity log |
| GET | `/api/logs` | List stored logs |
| GET | `/api/logs/{log_id}` | Get one log |
| DELETE | `/api/logs/{log_id}` | Delete one log |

These endpoints store and retrieve activity records only. They do not classify attacks or assign risk automatically.

### Example create request

```json
{
  "timestamp": "2026-09-14T10:30:00Z",
  "ip_address": "192.168.1.10",
  "attempts": 5,
  "commands": ["ls", "whoami"],
  "status": "suspicious",
  "risk_level": "medium"
}
```

`timestamp` is optional. If omitted, the server stores the current UTC time.

## Testing

1. Confirm the server starts without errors.
2. Open `/docs` and exercise each endpoint, or use the examples below from another PowerShell window.

Health:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Create a log:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/logs -ContentType "application/json" -Body '{"ip_address":"192.168.1.10","attempts":5,"commands":["ls","whoami"],"status":"suspicious","risk_level":"medium"}'
```

List logs, fetch one log, then delete it (replace `1` with the returned id):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/logs
Invoke-RestMethod http://127.0.0.1:8000/api/logs/1
Invoke-WebRequest -Method Delete -Uri http://127.0.0.1:8000/api/logs/1
```

Expected results:

- `GET /health` returns `{"status":"ok"}`
- Valid `POST /api/logs` returns HTTP 201 and the stored record
- Invalid payloads return HTTP 422
- Missing logs return HTTP 404
- SQLite data in `backend/ids.db` remains after restarting Uvicorn
