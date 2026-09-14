from datetime import timezone

from honeypot.parser.log_parser import (
    JsonlHoneypotParser,
    NormalizedEvent,
    ParseFailure,
    compute_event_hash,
    normalize_event_payload,
)


def test_parse_valid_json_event():
    event = normalize_event_payload(
        {
            "timestamp": "2026-09-14T10:30:00Z",
            "source_ip": "192.168.1.50",
            "event_type": "login_attempt",
            "username": "admin",
            "success": False,
            "command": None,
        }
    )
    assert isinstance(event, NormalizedEvent)
    assert event.source_ip == "192.168.1.50"
    assert event.event_type == "login_attempt"
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.tzinfo.utcoffset(event.timestamp) == timezone.utc.utcoffset(event.timestamp)


def test_missing_required_field():
    parser = JsonlHoneypotParser()
    result = parser.parse_line(
        '{"timestamp": "2026-09-14T10:30:00Z", "event_type": "login_attempt"}',
        line_number=3,
    )
    assert isinstance(result, ParseFailure)
    assert result.line_number == 3
    assert "source_ip" in result.reason


def test_invalid_timestamp():
    parser = JsonlHoneypotParser()
    result = parser.parse_line(
        '{"timestamp": "not-a-date", "source_ip": "192.168.1.50", "event_type": "login_attempt"}',
        line_number=4,
    )
    assert isinstance(result, ParseFailure)
    assert "timestamp" in result.reason


def test_malformed_json():
    parser = JsonlHoneypotParser()
    result = parser.parse_line("{not json", line_number=5)
    assert isinstance(result, ParseFailure)
    assert "malformed JSON" in result.reason


def test_login_event_parsing():
    event = normalize_event_payload(
        {
            "timestamp": "2026-09-14T10:30:00",
            "source_ip": "10.0.0.25",
            "event_type": "login_attempt",
            "username": "root",
            "success": False,
        }
    )
    assert event.event_type == "login_attempt"
    assert event.success is False
    assert event.command is None
    assert event.username == "root"


def test_command_event_parsing():
    event = normalize_event_payload(
        {
            "timestamp": "2026-09-14T10:31:12Z",
            "source_ip": "192.168.1.50",
            "event_type": "command",
            "username": "admin",
            "success": True,
            "command": "whoami",
        }
    )
    assert event.event_type == "command"
    assert event.command == "whoami"
    assert event.success is True


def test_password_fields_are_dropped():
    event = normalize_event_payload(
        {
            "timestamp": "2026-09-14T10:30:00Z",
            "source_ip": "192.168.1.50",
            "event_type": "login_attempt",
            "username": "admin",
            "password": "should-not-be-kept",
            "success": False,
        }
    )
    assert "password" not in event.to_dict()
    assert compute_event_hash(event)


def test_empty_lines_are_skipped(tmp_path):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-09-14T10:30:00Z", "source_ip": "192.168.1.50", "event_type": "login_attempt", "success": false}',
                "",
                '{"timestamp": "2026-09-14T10:31:12Z", "source_ip": "192.168.1.50", "event_type": "command", "command": "ls"}',
            ]
        ),
        encoding="utf-8",
    )
    events, failures = JsonlHoneypotParser().parse_file(log_file)
    assert len(events) == 2
    assert failures == []
