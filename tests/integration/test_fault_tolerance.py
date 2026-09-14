import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models import Detection
from ml.explainability.shap_explainer import ExplanationUnavailableError, explain_features
from ml.models.predict import InvalidFeatureInputError, ModelNotFoundError, predict_features
from ml.preprocessing.feature_schema import FEATURE_NAMES
from tests.support import load_fixture

pytestmark = pytest.mark.fault


def test_invalid_event_is_rejected(client):
    response = client.post(
        "/api/collector/events",
        json={
            "timestamp": "2026-09-14T12:00:00Z",
            "source_ip": "not-an-ip",
            "event_type": "login_attempt",
            "success": False,
        },
    )
    assert response.status_code == 422
    assert "traceback" not in response.text.lower()


def test_malformed_fixture_lines_are_failures_not_events():
    events, failures = load_fixture("malformed.jsonl")
    assert events == []
    assert len(failures) >= 5
    assert all(item.reason for item in failures)


def test_missing_model_returns_503(client, monkeypatch, tmp_path):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    payload = {name: 0 for name in FEATURE_NAMES}
    payload.update({"total_events": 2, "login_attempts": 1, "session_duration_seconds": 10})
    response = client.post("/api/detection/predict", json=payload)
    assert response.status_code == 503
    assert "train" in response.json()["detail"].lower()
    with pytest.raises(ModelNotFoundError):
        predict_features(payload, directory=tmp_path / "missing-model")


def test_shap_missing_model_does_not_invent_values(tmp_path):
    payload = {name: 1.0 for name in FEATURE_NAMES}
    with pytest.raises(ExplanationUnavailableError):
        explain_features(payload, directory=tmp_path / "missing")


def test_missing_feature_is_rejected(client):
    payload = {name: 0 for name in FEATURE_NAMES}
    payload.pop("failed_login_ratio")
    payload["classification"] = "normal"
    payload["confidence_score"] = 0.9
    response = client.post("/api/analysis/analyze", json=payload)
    assert response.status_code == 422


def test_nan_feature_is_rejected_by_predictor(tmp_path, monkeypatch):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    payload = {name: 0.0 for name in FEATURE_NAMES}
    payload["login_attempts"] = float("nan")
    with pytest.raises((InvalidFeatureInputError, ModelNotFoundError)):
        predict_features(payload, directory=tmp_path / "missing-model")


def test_empty_dashboard_does_not_invent_counts(client):
    stats = client.get("/api/dashboard/stats").json()
    assert stats == {
        "total_events": 0,
        "normal": 0,
        "suspicious": 0,
        "malicious": 0,
        "critical": 0,
        "active_alerts": 0,
    }
    assert client.get("/api/dashboard/timeline").json() == []
    assert client.get("/api/dashboard/alerts").json() == []


def test_websocket_disconnect_is_cleaned_up(client):
    from app.services.websocket_manager import get_connection_manager

    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        assert get_connection_manager().connection_count() == 1
    assert get_connection_manager().connection_count() == 0


def test_ingest_without_model_does_not_fabricate_detection(client, monkeypatch, tmp_path, db_session):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    response = client.post(
        "/api/collector/events",
        json={
            "timestamp": "2026-09-14T12:00:00Z",
            "source_ip": "203.0.113.77",
            "event_type": "login_attempt",
            "username": "admin",
            "success": False,
            "command": None,
        },
    )
    assert response.status_code == 200
    assert response.json()["attack_log"]["risk_level"] == "unscored"
    assert db_session.query(Detection).count() == 0


def test_database_error_does_not_leak_stack_trace(client, monkeypatch):
    def boom(*_args, **_kwargs):
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr("app.routes.logs.select", boom)
    response = client.get("/api/logs")
    assert response.status_code == 500
    body = response.json()
    assert "detail" in body
    assert "traceback" not in response.text.lower()
    assert "database unavailable" not in response.text.lower()
