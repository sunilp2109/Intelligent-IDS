# Honeypot data collection (Module 2)

This folder holds the **controlled/simulated** honeypot data source and the log parser.

The current files are **not** produced by a live Cowrie deployment. They use a JSON Lines format that is close enough to later replace with a Cowrie parser. Real Cowrie integration is a later step.

Do not expose a honeypot to the public internet from this project. Keep all testing local.

## Layout

```
honeypot/
├── logs/
│   └── sample_events.jsonl    # simulated raw honeypot output
├── parser/
│   └── log_parser.py          # JSONL parser → NormalizedEvent
└── scripts/
    └── import_logs.py         # batch import into the Module 1 database
```

Raw logs stay here. Processed activity is stored by the backend in SQLite (`backend/ids.db`), not in this folder.

## Raw log format

`logs/sample_events.jsonl` is JSON Lines. Each line is one honeypot event, which is **not** the AttackLog database schema.

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

```json
{
  "timestamp": "2026-09-14T10:31:12Z",
  "source_ip": "192.168.1.50",
  "event_type": "command",
  "username": "admin",
  "success": true,
  "command": "whoami"
}
```

Supported `event_type` values in this module: `login_attempt`, `command`.

The parser ignores sensitive keys such as `password` and never logs credential values.

## Normalized event format

Every parser, including a future Cowrie parser, should emit:

| Field | Meaning |
| --- | --- |
| `timestamp` | UTC datetime |
| `source_ip` | Normalized IPv4/IPv6 address |
| `event_type` | `login_attempt` or `command` |
| `username` | Optional |
| `success` | Optional boolean |
| `command` | Optional command string |

The ingestion service then maps normalized events onto the existing `AttackLog` table. It does not classify attacks or assign risk.

## Parser

`JsonlHoneypotParser` reads one line at a time, validates required fields, and returns structured `NormalizedEvent` objects. Malformed lines are reported and skipped.

`BaseHoneypotParser` is the extension point for later Cowrie logs:

```
Raw Honeypot Log → Parser → Normalized Event → Ingestion Service → Database
Cowrie Logs      → Cowrie Parser → same Normalized Event → same Ingestion Service → Database
```

## Batch import

From the project root, with the virtual environment active:

```powershell
python -m honeypot.scripts.import_logs
python -m honeypot.scripts.import_logs --file honeypot\logs\sample_events.jsonl
```

The same import is available from the running API:

```
POST /api/collector/import
```

Import is **not** run when FastAPI starts.
