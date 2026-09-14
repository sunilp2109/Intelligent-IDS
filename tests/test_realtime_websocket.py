from datetime import datetime, timezone

import pandas as pd
from starlette.websockets import WebSocketState

from app.models import AttackAnalysis, Detection, RiskAssessment
from app.services.realtime_service import (
    SENSITIVE_KEYS,
    build_security_event_payload,
    payload_contains_sensitive_data,
)
from app.services.websocket_manager import get_connection_manager
from ml.models.train import train_and_save
from ml.scripts.build_development_dataset import build_development_rows


def _login(ip: str, second: int, *, success: bool = False) -> dict:
    return {
        "timestamp": datetime(2026, 9, 14, 18, 30, second, tzinfo=timezone.utc).isoformat(),
        "source_ip": ip,
        "event_type": "login_attempt",
        "username": "admin",
        "success": success,
        "command": None,
    }


def _receive_until(ws, event_type: str, limit: int = 12) -> dict:
    seen = []
    for _ in range(limit):
        payload = ws.receive_json()
        seen.append(payload.get("event_type"))
        if payload.get("event_type") == event_type:
            return payload
    raise AssertionError(f"Did not receive {event_type}; saw {seen}")


def _train_model(monkeypatch, tmp_path):
    dataset = tmp_path / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path))


def test_websocket_connects_and_sends_status(client):
    with client.websocket_connect("/ws/events") as ws:
        payload = ws.receive_json()
        assert payload["event_type"] == "system_status"
        assert payload["data"]["status"] == "connected"
        assert get_connection_manager().connection_count() == 1
        assert "username" not in payload["data"]


def test_websocket_disconnect_cleans_up(client):
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        assert get_connection_manager().connection_count() == 1
    assert get_connection_manager().connection_count() == 0


def test_websocket_multiple_clients_receive_broadcast(client, monkeypatch, tmp_path):
    _train_model(monkeypatch, tmp_path)
    with client.websocket_connect("/ws/events") as ws1, client.websocket_connect("/ws/events") as ws2:
        assert ws1.receive_json()["event_type"] == "system_status"
        assert ws2.receive_json()["event_type"] == "system_status"
        assert get_connection_manager().connection_count() == 2
        response = client.post("/api/collector/events", json=_login("192.0.2.50", 1))
        assert response.status_code == 200
        first = _receive_until(ws1, "security_event")
        second = _receive_until(ws2, "security_event")
        assert first["data"]["log_id"] == second["data"]["log_id"]
        assert first["data"]["source_ip"] == "192.0.2.50"


def test_websocket_one_client_disconnect_does_not_stop_others(client, monkeypatch, tmp_path):
    _train_model(monkeypatch, tmp_path)
    with client.websocket_connect("/ws/events") as ws1:
        ws1.receive_json()
        with client.websocket_connect("/ws/events") as ws2:
            ws2.receive_json()
        assert get_connection_manager().connection_count() == 1
        response = client.post("/api/collector/events", json=_login("192.0.2.51", 2))
        assert response.status_code == 200
        payload = _receive_until(ws1, "security_event")
        assert payload["data"]["source_ip"] == "192.0.2.51"


def test_malformed_client_message_does_not_drop_connection(client):
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        ws.send_text("not-json{")
        ws.send_json({"type": "ping"})
        pong = _receive_until(ws, "system_status")
        assert pong["data"]["status"] == "ok"
        assert get_connection_manager().connection_count() == 1


def test_broadcast_failure_drops_unhealthy_client(client):
    import asyncio

    manager = get_connection_manager()

    class BoomSocket:
        def __init__(self):
            self.client_state = WebSocketState.CONNECTED

        async def send_json(self, _message):
            raise RuntimeError("broadcast failed")

        async def close(self):
            self.client_state = WebSocketState.DISCONNECTED

    boom = BoomSocket()
    manager._connections.append(boom)
    future = asyncio.run_coroutine_threadsafe(
        manager.broadcast(
            {
                "event_type": "system_status",
                "timestamp": "2026-09-14T18:30:00+00:00",
                "data": {"status": "ok"},
            }
        ),
        manager._loop,
    )
    future.result(timeout=5)
    assert boom not in manager.connections()


def test_ingest_without_model_does_not_invent_security_event(client, monkeypatch, tmp_path):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        response = client.post("/api/collector/events", json=_login("192.0.2.60", 3))
        assert response.status_code == 200
        payload = _receive_until(ws, "system_status")
        assert payload["data"]["status"] == "pipeline_incomplete"
        assert payload["data"]["reason"] == "model_unavailable"
        assert payload["data"]["log_id"] == response.json()["attack_log_id"]
        assert "classification" not in payload["data"]


def test_pipeline_broadcasts_complete_security_event(client, monkeypatch, tmp_path, db_session):
    _train_model(monkeypatch, tmp_path)
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        for second in range(8):
            response = client.post("/api/collector/events", json=_login("192.0.2.70", second, success=False))
            assert response.status_code == 200
        payload = _receive_until(ws, "security_event")
        data = payload["data"]
        assert payload["event_type"] == "security_event"
        assert data["log_id"] == response.json()["attack_log_id"]
        assert data["source_ip"] == "192.0.2.70"
        assert data["classification"] in {"normal", "suspicious", "malicious"}
        assert 0.0 <= data["confidence_score"] <= 1.0
        assert data["attack_category"]
        assert data["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert data["recommended_action"] in {"ALLOW", "ALERT", "BLOCK"}
        assert data["pipeline_status"] == "complete"
        assert data["xai_status"] in {"stored", "unavailable"}
        assert not payload_contains_sensitive_data(payload)
        assert SENSITIVE_KEYS.isdisjoint(data)
        assert "username" not in data
        assert "command" not in data
        assert "commands" not in data
        assert "explanation" not in data
        detection = db_session.get(Detection, data["detection_id"])
        assert detection is not None
        assert db_session.query(AttackAnalysis).filter_by(detection_id=detection.id).count() >= 1
        assert db_session.query(RiskAssessment).filter_by(detection_id=detection.id).count() >= 1


def test_security_event_payload_builder_omits_secrets():
    payload = build_security_event_payload(
        log_id=123,
        detection_id=9,
        source_ip="192.0.2.50",
        classification="malicious",
        confidence_score=0.94,
        attack_category="BRUTE_FORCE",
        risk_score=87,
        risk_level="CRITICAL",
        recommended_action="BLOCK",
        xai_status="stored",
        timestamp="2026-09-14T18:30:00+00:00",
    )
    assert payload["event_type"] == "security_event"
    assert payload["data"]["log_id"] == 123
    assert "username" not in payload["data"]
    assert not payload_contains_sensitive_data(payload)


def test_duplicate_ingest_does_not_broadcast_security_event(client, monkeypatch, tmp_path):
    _train_model(monkeypatch, tmp_path)
    event = _login("192.0.2.88", 4)
    first = client.post("/api/collector/events", json=event)
    assert first.status_code == 200
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        second = client.post("/api/collector/events", json=event)
        assert second.json()["result"] == "duplicate"
        ws.send_json({"type": "ping"})
        payload = ws.receive_json()
        assert payload["event_type"] == "system_status"
        assert payload["data"]["status"] == "ok"


def test_system_status_reports_websocket(client):
    status = client.get("/api/system/status").json()
    assert status["realtime"]["websocket_path"] == "/ws/events"
    assert status["realtime"]["authentication"] == "not_implemented"
    assert status["realtime"]["connected_clients"] == 0
