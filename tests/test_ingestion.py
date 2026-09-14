from app.models import AttackLog, HoneypotEvent
from app.services.ingestion import ingest_event, import_jsonl_file
from honeypot.parser.log_parser import normalize_event_payload


def _login_event():
    return normalize_event_payload(
        {
            "timestamp": "2026-09-14T10:30:00Z",
            "source_ip": "192.168.1.50",
            "event_type": "login_attempt",
            "username": "admin",
            "success": False,
            "command": None,
        }
    )


def test_valid_event_ingestion(client):
    response = client.post(
        "/api/collector/events",
        json={
            "timestamp": "2026-09-14T10:30:00Z",
            "source_ip": "192.168.1.50",
            "event_type": "login_attempt",
            "username": "admin",
            "success": False,
            "command": None,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "inserted"
    assert body["attack_log"]["ip_address"] == "192.168.1.50"
    assert body["attack_log"]["attempts"] == 1
    assert body["attack_log"]["status"] == "collected"
    assert body["attack_log"]["risk_level"] == "unscored"

    logs = client.get("/api/logs").json()
    assert len(logs) == 1
    assert logs[0]["attempts"] == 1


def test_invalid_event_rejection(client):
    response = client.post(
        "/api/collector/events",
        json={
            "timestamp": "2026-09-14T10:30:00Z",
            "source_ip": "not-an-ip",
            "event_type": "login_attempt",
            "success": False,
        },
    )
    assert response.status_code == 422

    missing = client.post(
        "/api/collector/events",
        json={
            "timestamp": "2026-09-14T10:30:00Z",
            "source_ip": "192.168.1.50",
            "event_type": "command",
        },
    )
    assert missing.status_code == 422


def test_duplicate_event_handling(db_session):
    event = _login_event()
    first = ingest_event(db_session, event)
    second = ingest_event(db_session, event)
    assert first.result == "inserted"
    assert second.result == "duplicate"
    assert first.event_hash == second.event_hash
    assert db_session.query(HoneypotEvent).count() == 1
    assert db_session.query(AttackLog).count() == 1


def test_batch_log_import(db_session, tmp_path):
    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-09-14T10:30:00Z", "source_ip": "192.168.1.50", "event_type": "login_attempt", "username": "admin", "success": false}',
                "{bad json",
                '{"timestamp": "not-a-date", "source_ip": "192.168.1.50", "event_type": "login_attempt"}',
                '{"source_ip": "192.168.1.50", "event_type": "login_attempt"}',
                '{"timestamp": "2026-09-14T10:31:12Z", "source_ip": "192.168.1.50", "event_type": "command", "command": "whoami"}',
                '{"timestamp": "2026-09-14T10:30:00Z", "source_ip": "192.168.1.50", "event_type": "login_attempt", "username": "admin", "success": false}',
            ]
        ),
        encoding="utf-8",
    )
    report = import_jsonl_file(db_session, mixed)
    assert report.parsed == 3
    assert report.inserted == 2
    assert report.duplicates == 1
    assert report.rejected == 3
    assert len(report.errors) == 3
    assert db_session.query(AttackLog).count() == 1
    assert db_session.query(HoneypotEvent).count() == 2


def test_api_batch_import_sample_file(client):
    response = client.post("/api/collector/import", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["inserted"] == 11
    assert body["rejected"] == 0
    logs = client.get("/api/logs").json()
    assert len(logs) == 3
    by_ip = {item["ip_address"]: item for item in logs}
    assert by_ip["192.168.1.50"]["attempts"] == 4
    assert by_ip["192.168.1.50"]["commands"] == ["whoami", "ls", "uname -a"]
    assert by_ip["10.0.0.25"]["attempts"] == 2
    assert by_ip["172.16.0.8"]["commands"] == ["id"]
