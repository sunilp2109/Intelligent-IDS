# Real-time monitoring (Module 9)

WebSocket streaming for newly processed security events. REST remains the source of truth for historical dashboard state.

```
Honeypot event
      ↓
Module 2 ingest
      ↓
Modules 3–7 (features → ML → analysis → SHAP → risk)
      ↓
Persist results
      ↓
WS /ws/events broadcast
      ↓
React dashboard live update
```

## WebSocket endpoint

`WS /ws/events`

Example (local development): `ws://127.0.0.1:8000/ws/events`

The server:

1. Checks the browser `Origin` against `CORS_ORIGINS` (missing Origin is allowed for tests/non-browser clients).
2. Accepts the socket and registers it in `ConnectionManager`.
3. Sends a `system_status` connected message.
4. Keeps the connection open until the client disconnects.
5. Broadcasts compact pipeline results to every remaining client.
6. Removes clients that disconnect or fail a send/timeout.

Rejected origins are closed with code `1008`.

## Connection manager

`backend/app/services/websocket_manager.py`

- `connect()` / `disconnect()`
- `broadcast()` (async, concurrent per client)
- `send_to_client()`
- `broadcast_threadsafe()` for sync ingest/pipeline code

A failed or slow client (`WS_SEND_TIMEOUT_SECONDS`, default 2s) is dropped. Other clients still receive the event.

## Event service

`backend/app/services/realtime_service.py` builds compact JSON and broadcasts it.

`backend/app/services/pipeline.py` `process_security_event()` is the integration point. It reuses existing ingest, feature, detection, analysis, explain, and risk services. It does **not** duplicate ML/XAI/risk math.

## Event types

| `event_type` | When |
| --- | --- |
| `system_status` | Connect, ping/pong, heartbeat, incomplete pipeline |
| `detection_created` | ML row persisted |
| `risk_assessed` | Risk row persisted |
| `security_event` | Final complete pipeline result (dashboard live feed) |
| `alert_created` | Same payload as `security_event` when `risk_level` is HIGH or CRITICAL |

The type field is a string so later modules can add values without renaming this one.

## Event payload

```json
{
  "event_type": "security_event",
  "timestamp": "2026-09-14T18:30:00+00:00",
  "data": {
    "log_id": 123,
    "detection_id": 9,
    "source_ip": "192.0.2.50",
    "classification": "malicious",
    "confidence_score": 0.94,
    "attack_category": "BRUTE_FORCE",
    "risk_score": 87,
    "risk_level": "CRITICAL",
    "recommended_action": "BLOCK",
    "xai_status": "stored",
    "pipeline_status": "complete"
  }
}
```

Values come from stored Module 4–7 results. Incomplete pipelines are **not** sent as `security_event`. If the trained model is missing, clients receive `system_status` with `reason=model_unavailable` instead of invented scores.

Payloads omit usernames, commands, credentials, filesystem paths, raw SHAP arrays, and feature dictionaries.

## Backend integration

`POST /api/collector/events` calls `process_security_event()`.

`POST /api/collector/import` still uses Module 2 ingest, then runs `run_session_pipeline()` once per AttackLog that received new events.

Duplicates are stored once and do not re-broadcast a security event.

## Frontend integration

`frontend/src/services/websocket.js` owns the single browser socket.

`RealtimeProvider` in `App.jsx` connects once for the operator console.

Dashboard pages:

- Load historical panels with REST (`/api/dashboard/*`).
- Append live rows from `security_event`.
- Debounce a REST refresh after each complete event so counters stay aligned with the database.
- On reconnect: clear the in-session overlay, reload REST, then resume the stream.

## Reconnection strategy

Delays: 1s, 2s, 4s, 8s, then 15s cap. Attempts reset after a successful open. Closing the page/component stops retries. This is not an aggressive tight loop.

## REST vs WebSocket

| REST | WebSocket |
| --- | --- |
| Historical stats, charts, logs, attack details | Newly created pipeline results |
| Source of truth after gaps | Best-effort live stream |
| Manual Refresh button | Connection status + live feed |

If the dashboard was disconnected, it must not assume it saw every event. Reconnect + REST refresh fills the gap.

## Keep-alive

`WS_HEARTBEAT_SECONDS` (default 30) sends `system_status` with `status=ok` while clients are connected. `0` disables heartbeats (tests). Clients may also send `{"type":"ping"}`.

## Security considerations

This WebSocket is for the **controlled project environment**.

There is **no authentication or authorization** for dashboard clients. Anyone who can reach the development server and pass the origin check can subscribe. Treat that as a known limitation and a future enhancement, not production-grade access control.

Do not expose this socket on a public network without adding auth.

## Testing procedure

Backend (project root, venv active):

```powershell
pytest tests/test_realtime_websocket.py -q
pytest -q
```

Frontend:

```powershell
cd frontend
npm test
```

## End-to-end procedure

1. Train the Module 4 model if `ml/artifacts/intrusion_model.joblib` is missing.
2. Start FastAPI on `127.0.0.1:8000`.
3. Start the Vite dashboard on `127.0.0.1:5173`.
4. Confirm the header shows **Connected**.
5. `POST /api/collector/events` with a controlled honeypot JSON body.
6. Confirm the live feed updates without a browser refresh.
7. Open a second tab; both should receive the same event. Close one tab; the other continues.

## Known limitations

- No WebSocket authentication.
- No automatic blocking or notifications.
- SHAP is stored on the detection row when the model exists; it is not streamed.
- Heartbeats are application JSON, not a production clustering fabric.
- Local development origins only (`CORS_ORIGINS`).
