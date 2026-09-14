from datetime import datetime, timezone

from ml.preprocessing.feature_extractor import extract_features, extract_session_features
from ml.preprocessing.feature_schema import FEATURE_NAMES, to_feature_vector


def _event(
    minute: int,
    second: int = 0,
    *,
    ip: str = "192.168.1.50",
    event_type: str = "login_attempt",
    username: str | None = "admin",
    success: bool | None = False,
    command: str | None = None,
) -> dict:
    return {
        "timestamp": datetime(2026, 9, 14, 10, minute, second, tzinfo=timezone.utc),
        "source_ip": ip,
        "event_type": event_type,
        "username": username,
        "success": success,
        "command": command,
    }


def test_empty_event_list():
    assert extract_features([]) == {}
    assert extract_features(None) == {}
    assert extract_session_features([]) == []


def test_one_login_attempt():
    features = extract_features([_event(30, success=False)])
    assert features["total_events"] == 1
    assert features["login_attempts"] == 1
    assert features["failed_login_attempts"] == 1
    assert features["successful_login_attempts"] == 0
    assert features["session_duration_seconds"] == 0.0
    assert features["attempts_per_minute"] == 60.0


def test_multiple_failed_login_attempts():
    events = [_event(30, second=index, success=False) for index in range(5)]
    features = extract_features(events)
    assert features["login_attempts"] == 5
    assert features["failed_login_attempts"] == 5
    assert features["successful_login_attempts"] == 0
    assert features["failed_login_ratio"] == 1.0


def test_successful_and_failed_login_attempts():
    events = [
        *[_event(30, second=index, success=False) for index in range(8)],
        _event(31, second=0, success=True),
        _event(31, second=1, success=True),
    ]
    features = extract_features(events)
    assert features["login_attempts"] == 10
    assert features["failed_login_attempts"] == 8
    assert features["successful_login_attempts"] == 2
    assert features["failed_login_ratio"] == 0.8


def test_multiple_commands():
    events = [
        _event(30, event_type="command", success=True, command="whoami"),
        _event(31, event_type="command", success=True, command="ls"),
        _event(32, event_type="command", success=True, command="id"),
    ]
    features = extract_features(events)
    assert features["command_count"] == 3
    assert features["unique_command_count"] == 3
    assert features["repeated_command_count"] == 0


def test_repeated_commands():
    events = [
        _event(30, event_type="command", success=True, command="whoami"),
        _event(31, event_type="command", success=True, command="ls"),
        _event(32, event_type="command", success=True, command="whoami"),
    ]
    features = extract_features(events)
    assert features["command_count"] == 3
    assert features["unique_command_count"] == 2
    assert features["repeated_command_count"] == 1


def test_unique_command_calculation():
    events = [
        _event(30, event_type="command", success=True, command="ls"),
        _event(31, event_type="command", success=True, command="ls"),
        _event(32, event_type="command", success=True, command="pwd"),
    ]
    features = extract_features(events)
    assert features["unique_command_count"] == 2


def test_failed_login_ratio_and_no_division_by_zero():
    commands_only = extract_features(
        [_event(30, event_type="command", success=True, command="ls")]
    )
    assert commands_only["login_attempts"] == 0
    assert commands_only["failed_login_ratio"] == 0.0
    mixed = extract_features(
        [
            _event(30, success=False),
            _event(31, success=False),
            _event(32, success=True),
        ]
    )
    assert mixed["failed_login_ratio"] == 0.666667


def test_attempts_per_minute():
    events = [
        _event(30, second=0, success=False),
        _event(31, second=0, success=False),
        _event(32, second=0, success=False),
    ]
    features = extract_features(events)
    assert features["session_duration_seconds"] == 120.0
    assert features["attempts_per_minute"] == 1.5


def test_commands_per_minute():
    events = [
        _event(30, event_type="command", success=True, command="whoami"),
        _event(32, event_type="command", success=True, command="ls"),
    ]
    features = extract_features(events)
    assert features["session_duration_seconds"] == 120.0
    assert features["commands_per_minute"] == 1.0


def test_session_duration():
    events = [_event(30, second=0), _event(32, second=30)]
    features = extract_features(events)
    assert features["session_duration_seconds"] == 150.0


def test_multiple_usernames():
    events = [
        _event(30, username="admin"),
        _event(31, username="root"),
        _event(32, username="admin"),
    ]
    features = extract_features(events)
    assert features["unique_username_count"] == 2


def test_multiple_source_ips():
    events = [
        _event(30, ip="192.168.1.50"),
        _event(31, ip="10.0.0.25"),
    ]
    features = extract_features(events)
    assert features["unique_source_ip_count"] == 2
    sessions = extract_session_features(events, window_minutes=30)
    assert len(sessions) == 2


def test_missing_optional_fields():
    features = extract_features(
        [
            {
                "timestamp": "2026-09-14T10:30:00Z",
                "source_ip": "192.168.1.50",
                "event_type": "login_attempt",
            }
        ]
    )
    assert features["login_attempts"] == 1
    assert features["failed_login_attempts"] == 0
    assert features["unique_username_count"] == 0
    assert features["command_count"] == 0


def test_invalid_timestamp_handling():
    features = extract_features(
        [
            {
                "timestamp": "not-a-date",
                "source_ip": "192.168.1.50",
                "event_type": "login_attempt",
                "success": False,
            },
            _event(30, success=False),
        ]
    )
    assert features["total_events"] == 1
    assert extract_features([{"source_ip": "192.168.1.50", "event_type": "login_attempt"}]) == {}


def test_feature_output_contains_all_expected_feature_names():
    features = extract_features(
        [
            _event(30, success=False),
            _event(31, event_type="command", success=True, command="wget http://example.invalid/file"),
        ]
    )
    assert list(features) == list(FEATURE_NAMES)
    vector = to_feature_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    assert features["suspicious_command_indicator"] == 1
    assert all(value == value and value not in (float("inf"), float("-inf")) for value in vector)
