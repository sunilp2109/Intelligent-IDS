from datetime import datetime, timezone

from app.models import Detection
from ml.preprocessing.feature_schema import FEATURE_NAMES


def _payload(**overrides):
    body = {name: 0 for name in FEATURE_NAMES}
    body.update(
        {
            "total_events": 2,
            "login_attempts": 1,
            "successful_login_attempts": 1,
            "unique_username_count": 1,
            "unique_source_ip_count": 1,
            "session_duration_seconds": 45,
            "events_per_minute": 2.67,
            "classification": "normal",
            "confidence_score": 0.91,
            "attack_category": "NORMAL_ACTIVITY",
            "evidence_strength": "LOW",
            "indicators": [],
        }
    )
    body.update(overrides)
    return body


def _brute_payload(**overrides):
    return _payload(
        total_events=23,
        login_attempts=20,
        failed_login_attempts=19,
        successful_login_attempts=1,
        failed_login_ratio=0.95,
        attempts_per_minute=12.0,
        command_count=3,
        unique_command_count=3,
        commands_per_minute=1.8,
        session_duration_seconds=100,
        events_per_minute=13.8,
        unique_username_count=2,
        classification="malicious",
        confidence_score=0.94,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
        indicators=[
            "HIGH_FAILED_LOGIN_RATIO",
            "HIGH_LOGIN_ATTEMPT_RATE",
            "HIGH_LOGIN_ATTEMPTS",
            "HIGH_FAILED_LOGIN_COUNT",
            "REPEATED_AUTHENTICATION_ATTEMPTS",
        ],
        **overrides,
    )


def test_risk_api_normal_response(client):
    response = client.post("/api/risk/assess", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] == "LOW"
    assert body["recommended_action"] == "ALLOW"
    assert 0 <= body["risk_score"] <= 100
    assert body["execution_status"] == "recommendation_only"
    assert "risk_breakdown" in body
    assert isinstance(body["decision_reason"], list)
    assert body["action_is_recommendation"] is True


def test_risk_api_malicious_response(client):
    response = client.post("/api/risk/assess", json=_brute_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "malicious"
    assert body["risk_level"] in {"HIGH", "CRITICAL"}
    assert body["recommended_action"] in {"ALERT", "BLOCK"}
    assert abs(sum(body["risk_breakdown"].values()) - body["risk_score"]) < 0.011


def test_risk_api_invalid_confidence(client):
    response = client.post("/api/risk/assess", json=_payload(confidence_score=1.5))
    assert response.status_code == 422


def test_risk_api_missing_classification(client):
    payload = _payload()
    payload.pop("classification")
    response = client.post("/api/risk/assess", json=payload)
    assert response.status_code == 422


def test_risk_api_invalid_attack_category(client):
    response = client.post("/api/risk/assess", json=_payload(attack_category="SQL_INJECTION"))
    assert response.status_code == 422
    assert "attack_category" in response.json()["detail"]


def test_risk_thresholds_endpoint(client):
    response = client.get("/api/risk/thresholds")
    assert response.status_code == 200
    body = response.json()
    assert body["classification_weights"]["malicious"] == 30.0
    assert "recommendation only" in body["action_note"]


def test_risk_persists_for_detection(client, db_session):
    created = client.post(
        "/api/logs",
        json={
            "ip_address": "192.168.1.80",
            "attempts": 4,
            "commands": [],
            "status": "collected",
            "risk_level": "unscored",
        },
    )
    assert created.status_code == 201
    log_id = created.json()["id"]
    detection = Detection(
        attack_log_id=log_id,
        classification="malicious",
        confidence_score=0.94,
        explanation=None,
    )
    db_session.add(detection)
    db_session.commit()
    db_session.refresh(detection)

    response = client.post("/api/risk/assess", json=_brute_payload(detection_id=detection.id))
    assert response.status_code == 200
    body = response.json()
    assert body["risk_id"] is not None
    assert body["detection_id"] == detection.id

    stored = client.get(f"/api/logs/{log_id}")
    assert stored.status_code == 200
    assert stored.json()["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    missing = client.post("/api/risk/assess", json=_brute_payload(detection_id=99999))
    assert missing.status_code == 404


def test_risk_from_existing_detection(client, db_session):
    for second in range(10):
        created = client.post(
            "/api/collector/events",
            json={
                "timestamp": datetime(2026, 9, 14, 10, 0, second, tzinfo=timezone.utc).isoformat(),
                "source_ip": "192.168.1.91",
                "event_type": "login_attempt",
                "username": "admin",
                "success": False,
                "command": None,
            },
        )
        assert created.status_code == 200
        log_id = created.json()["attack_log_id"]
    detection = Detection(
        attack_log_id=log_id,
        classification="malicious",
        confidence_score=0.91,
        explanation=None,
    )
    db_session.add(detection)
    db_session.commit()
    db_session.refresh(detection)

    analyzed = client.get(f"/api/analysis/{detection.id}")
    assert analyzed.status_code == 200
    assessed = client.get(f"/api/risk/{detection.id}")
    assert assessed.status_code == 200
    body = assessed.json()
    assert body["detection_id"] == detection.id
    assert body["risk_id"] is not None
    assert 0 <= body["risk_score"] <= 100
    assert body["recommended_action"] in {"ALLOW", "ALERT", "BLOCK"}
    missing = client.get("/api/risk/99999")
    assert missing.status_code == 404
