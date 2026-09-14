# Security monitoring dashboard (Module 8)

React operator console for the Intelligent IDS. The UI **displays** backend results. It does not predict, analyze, explain, or score risk.

```
FastAPI aggregates stored records
            ↓
GET /api/dashboard/* and /api/system/status
            ↓
    React dashboard (initial state)
            ↓
WS /ws/events live updates
```

The UI **displays** backend results. It does not predict, analyze, explain, or score risk. WebSocket messages never replace REST as the historical source of truth.

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

API calls live only in `src/services/api.js`. The live socket lives only in `src/services/websocket.js` (wrapped by `RealtimeProvider`).

Do not create extra WebSocket connections inside page components.

## Live monitoring

The header shows **Connecting / Connected / Disconnected** from the real socket state. It is not hard-coded.

After a drop, the client retries with 1s → 2s → 4s → 8s → 15s backoff, then reloads REST dashboard data before applying new live events.

The dashboard **Live security events** list is this browser session’s WebSocket buffer. Recent events/alerts also merge those rows (deduped by `detection_id`) so a reconnect cannot assume every missed message arrived.

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

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). CORS already allows this origin. The dashboard connects to `ws://127.0.0.1:8000/ws/events`.

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

WebSocket authentication is **not** implemented. Use the dashboard only in the controlled project environment.

Backend dashboard aggregation:

```powershell
pytest tests/test_dashboard_api.py -q
```
