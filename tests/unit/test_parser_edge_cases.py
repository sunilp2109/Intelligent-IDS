from honeypot.parser.log_parser import JsonlHoneypotParser, normalize_event_payload


def test_empty_timestamp_is_rejected():
    parser = JsonlHoneypotParser()
    result = parser.parse_line(
        '{"timestamp": "   ", "source_ip": "203.0.113.1", "event_type": "login_attempt"}',
        line_number=1,
    )
    assert result.reason


def test_invalid_event_type_is_rejected():
    parser = JsonlHoneypotParser()
    result = parser.parse_line(
        '{"timestamp": "2026-09-14T12:00:00Z", "source_ip": "203.0.113.1", "event_type": "exploit"}',
        line_number=2,
    )
    assert "event_type" in result.reason


def test_negative_success_non_boolean_is_rejected():
    try:
        normalize_event_payload(
            {
                "timestamp": "2026-09-14T12:00:00Z",
                "source_ip": "203.0.113.1",
                "event_type": "login_attempt",
                "success": "maybe",
            }
        )
        raised = False
    except (ValueError, TypeError):
        raised = True
    assert raised
