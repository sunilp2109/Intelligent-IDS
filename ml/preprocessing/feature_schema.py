from __future__ import annotations

from typing import Any

FEATURE_NAMES: tuple[str, ...] = (
    "total_events",
    "login_attempts",
    "failed_login_attempts",
    "successful_login_attempts",
    "command_count",
    "unique_command_count",
    "failed_login_ratio",
    "attempts_per_minute",
    "commands_per_minute",
    "unique_username_count",
    "unique_source_ip_count",
    "session_duration_seconds",
    "events_per_minute",
    "repeated_command_count",
    "suspicious_command_indicator",
)

FEATURE_DEFINITIONS: tuple[dict[str, str], ...] = (
    {
        "name": "total_events",
        "data_type": "int",
        "description": "Total number of valid events in the session.",
        "calculation": "Count of events that passed validation.",
    },
    {
        "name": "login_attempts",
        "data_type": "int",
        "description": "Number of login_attempt events.",
        "calculation": "Count of events where event_type == login_attempt.",
    },
    {
        "name": "failed_login_attempts",
        "data_type": "int",
        "description": "Number of unsuccessful login attempts.",
        "calculation": "Count of login_attempt events where success is False.",
    },
    {
        "name": "successful_login_attempts",
        "data_type": "int",
        "description": "Number of successful login attempts.",
        "calculation": "Count of login_attempt events where success is True.",
    },
    {
        "name": "command_count",
        "data_type": "int",
        "description": "Number of command events with a non-empty command string.",
        "calculation": "Count of events where event_type == command and command is present.",
    },
    {
        "name": "unique_command_count",
        "data_type": "int",
        "description": "Number of distinct command strings.",
        "calculation": "Count of unique command strings (case-sensitive).",
    },
    {
        "name": "failed_login_ratio",
        "data_type": "float",
        "description": "Share of login attempts that failed.",
        "calculation": "failed_login_attempts / login_attempts. Returns 0.0 when login_attempts is 0.",
    },
    {
        "name": "attempts_per_minute",
        "data_type": "float",
        "description": "Login-attempt frequency over the observed session.",
        "calculation": "login_attempts / (duration_seconds / 60). Duration below 1 second is treated as 1 second.",
    },
    {
        "name": "commands_per_minute",
        "data_type": "float",
        "description": "Command frequency over the observed session.",
        "calculation": "command_count / (duration_seconds / 60). Duration below 1 second is treated as 1 second.",
    },
    {
        "name": "unique_username_count",
        "data_type": "int",
        "description": "Number of distinct usernames observed.",
        "calculation": "Count of unique non-empty username values.",
    },
    {
        "name": "unique_source_ip_count",
        "data_type": "int",
        "description": "Number of distinct source IP addresses in the session.",
        "calculation": "Count of unique source_ip values.",
    },
    {
        "name": "session_duration_seconds",
        "data_type": "float",
        "description": "Elapsed time between the earliest and latest event.",
        "calculation": "max(timestamp) - min(timestamp) in seconds. Single-event sessions are 0.0.",
    },
    {
        "name": "events_per_minute",
        "data_type": "float",
        "description": "Overall event frequency over the observed session.",
        "calculation": "total_events / (duration_seconds / 60). Duration below 1 second is treated as 1 second.",
    },
    {
        "name": "repeated_command_count",
        "data_type": "int",
        "description": "How many command occurrences are repeats of an earlier command.",
        "calculation": "command_count - unique_command_count.",
    },
    {
        "name": "suspicious_command_indicator",
        "data_type": "int",
        "description": "Heuristic flag for documented suspicious command substrings. This is a feature, not an attack label.",
        "calculation": "1 if any command contains a documented pattern, otherwise 0.",
    },
)


def to_feature_vector(features: dict[str, Any]) -> list[float]:
    """Return features in a stable order suitable for a future scikit-learn matrix."""
    return [float(features[name]) for name in FEATURE_NAMES]
