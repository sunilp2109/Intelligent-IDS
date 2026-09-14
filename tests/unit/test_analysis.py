from datetime import datetime, timezone

from app.models import Detection
from ml.analysis.analyzer import AnalysisInputError, analyze_activity
from ml.analysis.thresholds import DEFAULT_THRESHOLDS
from ml.preprocessing.feature_schema import FEATURE_NAMES


def _features(**overrides) -> dict:
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
        }
    )
    body.update(overrides)
    return body


def _prediction(classification="malicious", confidence=0.94) -> dict:
    return {"classification": classification, "confidence_score": confidence}


def test_normal_activity_has_no_attack_category():
    result = analyze_activity(_features(), _prediction("normal", 0.91))
    assert result["classification"] == "normal"
    assert result["attack_category"] == "NORMAL_ACTIVITY"
    assert result["indicators"] == []
    assert result["secondary_categories"] == []
    assert result["ml_confidence"] == 0.91
    assert result["feature_names"] == list(FEATURE_NAMES)
    assert result["features"]["login_attempts"] == 1


def test_brute_force_like_behavior():
    features = _features(
        total_events=23,
        login_attempts=20,
        failed_login_attempts=19,
        successful_login_attempts=1,
        failed_login_ratio=0.95,
        attempts_per_minute=12.0,
        command_count=3,
        unique_command_count=3,
        session_duration_seconds=100,
        events_per_minute=13.8,
        unique_username_count=2,
    )
    result = analyze_activity(features, _prediction("malicious", 0.94))
    assert result["attack_category"] == "BRUTE_FORCE"
    assert result["classification"] == "malicious"
    assert "HIGH_FAILED_LOGIN_RATIO" in result["indicators"]
    assert "HIGH_LOGIN_ATTEMPT_RATE" in result["indicators"]
    assert "REPEATED_AUTHENTICATION_ATTEMPTS" in result["indicators"]
    assert result["evidence"]["login_attempts"] == 20
    assert result["evidence"]["failed_login_attempts"] == 19
    assert result["evidence"]["failed_login_ratio"] == 0.95
    assert result["evidence"]["attempts_per_minute"] == 12.0
    assert result["ml_confidence"] == 0.94
    assert result["evidence_strength"] == "HIGH"
    assert result["features"]["login_attempts"] == 20


def test_repeated_authentication_attempts_without_brute_force():
    features = _features(
        total_events=6,
        login_attempts=6,
        failed_login_attempts=6,
        successful_login_attempts=0,
        failed_login_ratio=1.0,
        attempts_per_minute=4.0,
        session_duration_seconds=90,
        events_per_minute=4.0,
    )
    result = analyze_activity(features, _prediction("suspicious", 0.72))
    assert result["attack_category"] == "REPEATED_AUTHENTICATION_ATTEMPTS"
    assert "BRUTE_FORCE" not in result["secondary_categories"]
    assert "REPEATED_AUTHENTICATION_ATTEMPTS" in result["indicators"]
    assert result["evidence"]["login_attempts"] == 6


def test_suspicious_command_activity():
    features = _features(
        total_events=4,
        login_attempts=1,
        successful_login_attempts=1,
        command_count=3,
        unique_command_count=2,
        repeated_command_count=1,
        suspicious_command_indicator=1,
        commands_per_minute=2.0,
        session_duration_seconds=80,
    )
    result = analyze_activity(features, _prediction("malicious", 0.88))
    assert result["attack_category"] == "SUSPICIOUS_COMMAND_ACTIVITY"
    assert "SUSPICIOUS_COMMAND_PATTERN" in result["indicators"]
    assert result["evidence"]["suspicious_command_indicator"] == 1


def test_abnormal_frequency():
    features = _features(
        total_events=20,
        login_attempts=2,
        successful_login_attempts=2,
        command_count=2,
        events_per_minute=40.0,
        session_duration_seconds=30,
        unique_username_count=1,
    )
    result = analyze_activity(features, _prediction("suspicious", 0.67))
    assert result["attack_category"] == "ABNORMAL_REQUEST_ACTIVITY"
    assert "HIGH_EVENT_FREQUENCY" in result["indicators"]
    assert "SHORT_DURATION_HIGH_VOLUME" in result["indicators"]


def test_multiple_indicators_and_secondary_category():
    features = _features(
        total_events=25,
        login_attempts=20,
        failed_login_attempts=19,
        successful_login_attempts=1,
        failed_login_ratio=0.95,
        attempts_per_minute=12.0,
        command_count=4,
        unique_command_count=3,
        repeated_command_count=1,
        suspicious_command_indicator=1,
        session_duration_seconds=100,
        events_per_minute=15.0,
        unique_username_count=3,
    )
    result = analyze_activity(features, _prediction("malicious", 0.96))
    assert result["primary_category"] == "BRUTE_FORCE"
    assert "SUSPICIOUS_COMMAND_ACTIVITY" in result["secondary_categories"]
    assert "UNAUTHORIZED_ACCESS_ATTEMPT" in result["secondary_categories"]
    assert len(result["indicators"]) >= 4


def test_unknown_suspicious_behavior():
    result = analyze_activity(_features(), _prediction("malicious", 0.81))
    assert result["attack_category"] == "UNKNOWN_SUSPICIOUS_ACTIVITY"
    assert result["insufficient_evidence_reason"]
    assert "no supported behavioral category" in result["insufficient_evidence_reason"]


def test_missing_feature():
    payload = _features()
    payload.pop("failed_login_ratio")
    try:
        analyze_activity(payload, _prediction())
        raise AssertionError("expected AnalysisInputError")
    except AnalysisInputError as exc:
        assert "failed_login_ratio" in str(exc)


def test_invalid_feature_values():
    try:
        analyze_activity(_features(login_attempts=float("nan")), _prediction())
        raise AssertionError("expected AnalysisInputError")
    except AnalysisInputError as exc:
        assert "NaN" in str(exc)


def test_ml_prediction_missing():
    try:
        analyze_activity(_features(), None)
        raise AssertionError("expected AnalysisInputError")
    except AnalysisInputError as exc:
        assert "missing" in str(exc).lower()
    try:
        analyze_activity(_features(), {"classification": "malicious"})
        raise AssertionError("expected AnalysisInputError")
    except AnalysisInputError as exc:
        assert "confidence_score" in str(exc)


def test_low_confidence_ml_prediction_still_uses_features():
    features = _features(
        total_events=20,
        login_attempts=20,
        failed_login_attempts=19,
        successful_login_attempts=1,
        failed_login_ratio=0.95,
        attempts_per_minute=12.0,
        session_duration_seconds=100,
    )
    result = analyze_activity(features, _prediction("malicious", 0.31))
    assert result["ml_confidence"] == 0.31
    assert result["ml_confidence_low"] is True
    assert result["attack_category"] == "BRUTE_FORCE"


def test_boundary_values_for_brute_force_threshold():
    below = _features(
        login_attempts=DEFAULT_THRESHOLDS.brute_force_min_attempts - 1,
        failed_login_attempts=DEFAULT_THRESHOLDS.brute_force_min_failed,
        failed_login_ratio=0.86,
        session_duration_seconds=60,
        attempts_per_minute=6.0,
        total_events=7,
    )
    above = _features(
        login_attempts=DEFAULT_THRESHOLDS.brute_force_min_attempts,
        failed_login_attempts=DEFAULT_THRESHOLDS.brute_force_min_failed,
        failed_login_ratio=DEFAULT_THRESHOLDS.brute_force_min_failed_ratio,
        session_duration_seconds=60,
        attempts_per_minute=8.0,
        total_events=8,
    )
    below_result = analyze_activity(below, _prediction("suspicious", 0.7))
    above_result = analyze_activity(above, _prediction("suspicious", 0.7))
    assert below_result["attack_category"] != "BRUTE_FORCE"
    assert above_result["attack_category"] == "BRUTE_FORCE"


def test_single_event_rate_is_not_treated_as_flood():
    features = _features(
        total_events=1,
        login_attempts=1,
        failed_login_attempts=1,
        successful_login_attempts=0,
        failed_login_ratio=1.0,
        attempts_per_minute=60.0,
        events_per_minute=60.0,
        session_duration_seconds=0.0,
    )
    result = analyze_activity(features, _prediction("suspicious", 0.6))
    assert "HIGH_LOGIN_ATTEMPT_RATE" not in result["indicators"]
    assert "HIGH_EVENT_FREQUENCY" not in result["indicators"]
    assert result["attack_category"] == "UNKNOWN_SUSPICIOUS_ACTIVITY"


def test_analyze_api_and_thresholds(client):
    payload = _features(
        total_events=23,
        login_attempts=20,
        failed_login_attempts=19,
        successful_login_attempts=1,
        failed_login_ratio=0.95,
        attempts_per_minute=12.0,
        session_duration_seconds=100,
        classification="malicious",
        confidence_score=0.94,
    )
    response = client.post("/api/analysis/analyze", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["attack_category"] == "BRUTE_FORCE"
    assert body["evidence"]["login_attempts"] == 20
    assert body["ml_confidence"] == 0.94
    thresholds = client.get("/api/analysis/thresholds")
    assert thresholds.status_code == 200
    assert "brute_force_min_attempts" in thresholds.json()


def test_analyze_api_rejects_missing_classification(client):
    payload = _features(login_attempts=2)
    response = client.post("/api/analysis/analyze", json=payload)
    assert response.status_code == 422


def test_database_integration_analyzes_existing_detection(client, db_session):
    log_id = None
    for second in range(10):
        created = client.post(
            "/api/collector/events",
            json={
                "timestamp": datetime(2026, 9, 14, 10, 0, second, tzinfo=timezone.utc).isoformat(),
                "source_ip": "192.168.1.90",
                "event_type": "login_attempt",
                "username": "admin" if second % 2 == 0 else "root",
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

    response = client.get(f"/api/analysis/{detection.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "malicious"
    assert body["attack_category"] in {
        "BRUTE_FORCE",
        "REPEATED_AUTHENTICATION_ATTEMPTS",
        "UNKNOWN_SUSPICIOUS_ACTIVITY",
    }
    assert body["evidence"]["login_attempts"] == 10
    assert body["features"]["failed_login_attempts"] == 10
    assert body["analysis_id"] is not None
    assert body["detection_id"] == detection.id
    missing = client.get("/api/analysis/99999")
    assert missing.status_code == 404
