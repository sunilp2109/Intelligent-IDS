from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from typing import Any

logger = logging.getLogger("intelligent_ids.parser")

ALLOWED_EVENT_TYPES = frozenset({"login_attempt", "command"})
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "credential",
        "credentials",
        "private_key",
        "ssh_key",
    }
)


@dataclass(frozen=True)
class NormalizedEvent:
    timestamp: datetime
    source_ip: str
    event_type: str
    username: str | None
    success: bool | None
    command: str | None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        return payload


@dataclass(frozen=True)
class ParseFailure:
    line_number: int
    reason: str


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("timestamp is empty")
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError("timestamp is invalid") from exc
    else:
        raise ValueError("timestamp is invalid")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_source_ip(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("source_ip is required")
    try:
        return str(ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc


def _optional_text(value: Any, field_name: str, max_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} is too long")
    return cleaned


def _optional_bool(value: Any, field_name: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ValueError(f"{field_name} must be a boolean")


def normalize_event_payload(payload: dict[str, Any], *, line_number: int = 0) -> NormalizedEvent:
    """Convert a raw event dictionary into a source-independent normalized event."""
    if not isinstance(payload, dict):
        raise ValueError("event must be a JSON object")

    sanitized = {key: value for key, value in payload.items() if str(key).lower() not in SENSITIVE_KEYS}

    missing = [field for field in ("timestamp", "source_ip", "event_type") if field not in sanitized or sanitized[field] in (None, "")]
    if missing:
        raise ValueError(f"missing required field: {', '.join(missing)}")

    event_type_raw = sanitized["event_type"]
    if not isinstance(event_type_raw, str):
        raise ValueError("event_type must be a string")
    event_type = event_type_raw.strip().lower()
    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError(f"unsupported event_type: {event_type_raw}")

    command = _optional_text(sanitized.get("command"), "command", 512)
    if event_type == "command" and command is None:
        raise ValueError("command events require a command")

    event = NormalizedEvent(
        timestamp=parse_timestamp(sanitized["timestamp"]),
        source_ip=parse_source_ip(sanitized["source_ip"]),
        event_type=event_type,
        username=_optional_text(sanitized.get("username"), "username", 128),
        success=_optional_bool(sanitized.get("success"), "success"),
        command=command,
    )
    logger.info(
        "Event parsed line=%s type=%s ip=%s",
        line_number or "-",
        event.event_type,
        event.source_ip,
    )
    return event


def compute_event_hash(event: NormalizedEvent) -> str:
    canonical = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


class BaseHoneypotParser(ABC):
    """Source-specific parsers should convert raw logs into NormalizedEvent objects.

    A future Cowrie parser can implement the same interface without changing
    ingestion or the AttackLog database layer.
    """

    @abstractmethod
    def parse_line(self, line: str, line_number: int = 0) -> NormalizedEvent | ParseFailure | None:
        raise NotImplementedError

    def parse_file(self, path: str | Path) -> tuple[list[NormalizedEvent], list[ParseFailure]]:
        log_path = Path(path)
        logger.info("Log file loaded path=%s", log_path)
        events: list[NormalizedEvent] = []
        failures: list[ParseFailure] = []
        with log_path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                result = self.parse_line(raw_line, line_number)
                if isinstance(result, ParseFailure):
                    failures.append(result)
                    logger.warning(
                        "Event rejected line=%s reason=%s",
                        result.line_number,
                        result.reason,
                    )
                elif result is not None:
                    events.append(result)
        return events, failures


class JsonlHoneypotParser(BaseHoneypotParser):
    """Parser for the current simulated honeypot JSON Lines format."""

    def parse_line(self, line: str, line_number: int = 0) -> NormalizedEvent | ParseFailure | None:
        stripped = line.strip()
        if not stripped:
            return None
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return ParseFailure(line_number=line_number, reason=f"malformed JSON: {exc.msg}")
        try:
            return normalize_event_payload(payload, line_number=line_number)
        except ValueError as exc:
            return ParseFailure(line_number=line_number, reason=str(exc))
