from ml.preprocessing.feature_extractor import extract_features
from tests.support import load_fixture


def test_nan_and_missing_timestamp_events_are_dropped():
    features = extract_features(
        [
            {"timestamp": None, "source_ip": "203.0.113.1", "event_type": "login_attempt", "success": False},
            {
                "timestamp": "2026-09-14T12:00:00Z",
                "source_ip": "203.0.113.1",
                "event_type": "login_attempt",
                "success": False,
            },
        ]
    )
    assert features["total_events"] == 1
    assert features["login_attempts"] == 1


def test_empty_command_does_not_count_as_a_command():
    features = extract_features(
        [
            {
                "timestamp": "2026-09-14T12:00:00Z",
                "source_ip": "203.0.113.1",
                "event_type": "command",
                "command": "",
                "success": True,
            },
            {
                "timestamp": "2026-09-14T12:00:05Z",
                "source_ip": "203.0.113.1",
                "event_type": "command",
                "command": "ls",
                "success": True,
            },
        ]
    )
    assert features["command_count"] == 1
    assert features["unique_command_count"] == 1


def test_fixture_normal_activity_rates_are_finite():
    events, failures = load_fixture("normal_activity.jsonl")
    assert failures == []
    features = extract_features([event.to_dict() for event in events])
    assert features["login_attempts"] == 1
    assert features["failed_login_ratio"] == 0.0
    assert features["session_duration_seconds"] >= 0
    assert features["attempts_per_minute"] == features["attempts_per_minute"]
