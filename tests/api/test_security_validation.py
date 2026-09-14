import pytest

from ml.preprocessing.feature_schema import FEATURE_NAMES

pytestmark = pytest.mark.security


def test_websocket_payload_omits_credentials(client, monkeypatch, tmp_path):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    with client.websocket_connect("/ws/events") as ws:
        connected = ws.receive_json()
        assert "password" not in str(connected).lower()
        assert "secret" not in str(connected).lower()
        client.post(
            "/api/collector/events",
            json={
                "timestamp": "2026-09-14T12:00:00Z",
                "source_ip": "203.0.113.88",
                "event_type": "login_attempt",
                "username": "admin",
                "success": False,
                "command": None,
            },
        )
        status = ws.receive_json()
        blob = str(status).lower()
        assert "password" not in blob
        assert "admin" not in blob or status["event_type"] == "system_status"
        assert "command" not in (status.get("data") or {})


def test_health_does_not_expose_env(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "DATABASE_URL" not in response.text
    assert "secret" not in response.text.lower()


def test_oversized_command_is_rejected(client):
    response = client.post(
        "/api/collector/events",
        json={
            "timestamp": "2026-09-14T12:00:00Z",
            "source_ip": "203.0.113.88",
            "event_type": "command",
            "command": "x" * 5000,
            "success": True,
        },
    )
    assert response.status_code == 422


def test_wrong_types_are_rejected(client):
    response = client.post(
        "/api/logs",
        json={
            "ip_address": "203.0.113.88",
            "attempts": "plenty",
            "commands": "whoami",
            "status": "collected",
            "risk_level": "unscored",
        },
    )
    assert response.status_code == 422


def test_risk_action_is_recommendation_only(client):
    payload = {name: 0 for name in FEATURE_NAMES}
    payload.update(
        {
            "classification": "malicious",
            "confidence_score": 0.94,
            "attack_category": "BRUTE_FORCE",
            "evidence_strength": "HIGH",
            "login_attempts": 20,
            "failed_login_attempts": 19,
            "failed_login_ratio": 0.95,
            "attempts_per_minute": 12,
            "session_duration_seconds": 100,
            "total_events": 23,
        }
    )
    response = client.post("/api/risk/assess", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["execution_status"] == "recommendation_only"
    assert body["action_is_recommendation"] is True
    assert "firewall" not in response.text.lower()


def test_system_status_documents_missing_websocket_auth(client):
    status = client.get("/api/system/status").json()
    assert status["realtime"]["authentication"] == "not_implemented"
    notes = " ".join(status.get("notes") or []).lower()
    assert "authenticated" in notes or "not authenticated" in notes or "not_implemented" in status["realtime"]["authentication"]
