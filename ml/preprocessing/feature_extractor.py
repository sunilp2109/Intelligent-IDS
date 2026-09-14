from __future__ import annotations

import csv
import math
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from honeypot.parser.log_parser import NormalizedEvent, parse_timestamp
from ml.preprocessing.feature_schema import FEATURE_NAMES, to_feature_vector

DEFAULT_SESSION_WINDOW_MINUTES = int(os.getenv("COLLECTOR_SESSION_WINDOW_MINUTES", "30"))
MIN_RATE_DURATION_SECONDS = 1.0
FEATURE_ROUNDING = 6

# Substring patterns used only as a transparent heuristic feature.
# A match does not classify the session as an attack.
SUSPICIOUS_COMMAND_PATTERNS: tuple[str, ...] = (
    "wget",
    "curl",
    "nmap",
    "netcat",
    "/etc/passwd",
    "/etc/shadow",
    "chmod 777",
    "python -c",
    "bash -i",
    "iptables",
    "useradd",
    "hydra",
    "ssh-keygen",
)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _finite(value: float) -> float:
    if math.isnan(value) or math.isinf(value):
        return 0.0
    return round(value, FEATURE_ROUNDING)


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return _finite(numerator / denominator)


def _per_minute(count: int, duration_seconds: float) -> float:
    duration = duration_seconds if duration_seconds >= MIN_RATE_DURATION_SECONDS else MIN_RATE_DURATION_SECONDS
    return _finite(count / (duration / 60.0))


def _event_mapping(event: Any) -> Mapping[str, Any] | None:
    if isinstance(event, NormalizedEvent):
        return event.to_dict()
    if isinstance(event, Mapping):
        return event
    return None


def _coerce_event(event: Any) -> dict[str, Any] | None:
    payload = _event_mapping(event)
    if payload is None:
        return None
    try:
        timestamp = parse_timestamp(payload.get("timestamp"))
        source_ip = str(payload.get("source_ip") or "").strip()
        event_type = str(payload.get("event_type") or "").strip().lower()
    except (TypeError, ValueError):
        return None
    if not source_ip or not event_type:
        return None

    username = payload.get("username")
    command = payload.get("command")
    success = payload.get("success")
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "username": username.strip() if isinstance(username, str) and username.strip() else None,
        "success": success if isinstance(success, bool) else None,
        "command": command.strip() if isinstance(command, str) and command.strip() else None,
    }


def _command_is_suspicious(command: str) -> bool:
    lowered = command.lower()
    return any(pattern in lowered for pattern in SUSPICIOUS_COMMAND_PATTERNS)


def extract_features(events: Iterable[Any] | None) -> dict[str, Any]:
    """Calculate one behavioral feature vector from a session of normalized events.

    An empty or fully invalid input returns an empty dictionary.
    """
    if not events:
        return {}

    parsed = [item for item in (_coerce_event(event) for event in events) if item is not None]
    if not parsed:
        return {}

    parsed.sort(key=lambda item: item["timestamp"])
    timestamps = [item["timestamp"] for item in parsed]
    duration_seconds = max((_as_utc(timestamps[-1]) - _as_utc(timestamps[0])).total_seconds(), 0.0)

    login_events = [item for item in parsed if item["event_type"] == "login_attempt"]
    command_events = [item for item in parsed if item["event_type"] == "command" and item["command"]]
    commands = [item["command"] for item in command_events]
    usernames = {item["username"] for item in parsed if item["username"]}
    source_ips = {item["source_ip"] for item in parsed}

    login_attempts = len(login_events)
    failed_login_attempts = sum(1 for item in login_events if item["success"] is False)
    successful_login_attempts = sum(1 for item in login_events if item["success"] is True)
    command_count = len(commands)
    unique_commands = set(commands)

    features = {
        "total_events": len(parsed),
        "login_attempts": login_attempts,
        "failed_login_attempts": failed_login_attempts,
        "successful_login_attempts": successful_login_attempts,
        "command_count": command_count,
        "unique_command_count": len(unique_commands),
        "failed_login_ratio": _safe_ratio(failed_login_attempts, login_attempts),
        "attempts_per_minute": _per_minute(login_attempts, duration_seconds),
        "commands_per_minute": _per_minute(command_count, duration_seconds),
        "unique_username_count": len(usernames),
        "unique_source_ip_count": len(source_ips),
        "session_duration_seconds": _finite(duration_seconds),
        "events_per_minute": _per_minute(len(parsed), duration_seconds),
        "repeated_command_count": command_count - len(unique_commands),
        "suspicious_command_indicator": int(any(_command_is_suspicious(command) for command in commands)),
    }
    return {name: features[name] for name in FEATURE_NAMES}


def group_events_into_sessions(
    events: Iterable[Any] | None,
    window_minutes: int | None = None,
) -> list[list[dict[str, Any]]]:
    """Group events by source IP and temporal proximity.

    A new session starts when an event's timestamp is more than `window_minutes`
    after the first event of the current session for that IP. Username is recorded
    as a feature, not used as a grouping key, so brute-force username cycling stays
    in one behavioral session.

    This does not assume that one IP always equals one attacker; it is a first
    sessionization rule that can be replaced later.
    """
    parsed = [item for item in (_coerce_event(event) for event in events or []) if item is not None]
    if not parsed:
        return []

    window = timedelta(minutes=window_minutes or DEFAULT_SESSION_WINDOW_MINUTES)
    parsed.sort(key=lambda item: (item["source_ip"], item["timestamp"]))

    sessions: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_ip: str | None = None
    session_start: datetime | None = None

    for event in parsed:
        ip_address = event["source_ip"]
        timestamp = _as_utc(event["timestamp"])
        if (
            current_ip != ip_address
            or session_start is None
            or timestamp - session_start > window
        ):
            if current:
                sessions.append(current)
            current = [event]
            current_ip = ip_address
            session_start = timestamp
            continue
        current.append(event)

    if current:
        sessions.append(current)
    return sessions


def extract_session_features(
    events: Iterable[Any] | None,
    window_minutes: int | None = None,
) -> list[dict[str, Any]]:
    """Sessionize events and return one feature vector per session."""
    results: list[dict[str, Any]] = []
    for session in group_events_into_sessions(events, window_minutes=window_minutes):
        features = extract_features(session)
        if not features:
            continue
        source_ips = sorted({item["source_ip"] for item in session})
        timestamps = [item["timestamp"] for item in session]
        results.append(
            {
                "source_ip": source_ips[0] if len(source_ips) == 1 else None,
                "source_ips": source_ips,
                "session_start": min(timestamps).isoformat(),
                "session_end": max(timestamps).isoformat(),
                "features": features,
                "feature_vector": to_feature_vector(features),
            }
        )
    return results


def write_features_csv(records: Sequence[Mapping[str, Any]], path: str | Path) -> Path:
    """Write identifier columns plus the behavioral feature vector to CSV."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["source_ip", "session_start", "session_end", *FEATURE_NAMES]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            features = record.get("features", record)
            row = {
                "source_ip": record.get("source_ip", ""),
                "session_start": record.get("session_start", ""),
                "session_end": record.get("session_end", ""),
            }
            row.update({name: features.get(name, "") for name in FEATURE_NAMES})
            writer.writerow(row)
    return output
