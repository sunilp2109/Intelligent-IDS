# Security monitoring dashboard (Module 8)

React operator console for the Intelligent IDS. The UI **displays** backend results. It does not predict, analyze, explain, or score risk.

```
FastAPI aggregates stored records
            ↓
GET /api/dashboard/* and /api/system/status
            ↓
React dashboard
```

## Pages

| Route | Page |
| --- | --- |
| `/` | Dashboard — stats, timeline, attack/risk charts, recent events, alerts |
| `/alerts` | Filterable HIGH/CRITICAL (and other) alerts |
| `/logs` | Activity logs with IP / classification / risk filters |
| `/analysis` | Attack-category distribution and detections |
| `/events/:id` | Detection detail: ML, analysis, risk breakdown, stored SHAP |
| `/status` | Backend, database, ML artifact, collector mode |

## Components

- `layout/AppShell.jsx` — sidebar navigation
- `cards/StatCard.jsx` — summary metrics
- `charts/` — Recharts timeline, attack donut, risk bars, SHAP bars
- `tables/EventsTable.jsx`
- `alerts/AlertList.jsx`
- `common/` — loading / empty / error / badges

API calls live only in `src/services/api.js`.

## Environment

Copy `frontend/.env.example` to `frontend/.env` if needed:

```
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Do not hard-code the API origin in components. Do not put secrets in this file.

## Run

Backend (project root venv):

```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). CORS already allows this origin.

## Empty state

If the database has no events, stats are zeros and charts/tables show “No security events recorded.” / “No active alerts.” The UI never fills in demo numbers by itself.

## Demo data

Optional, labeled `status=demo`, not started by the API:

```powershell
python -m scripts.seed_demo_data
```

Prefer exercising the real Modules 4–7 APIs when a trained model exists. The seed script does **not** fabricate SHAP values.

## Tests

```powershell
cd frontend
npm test
```

Backend dashboard aggregation:

```powershell
pytest tests/test_dashboard_api.py -q
```
