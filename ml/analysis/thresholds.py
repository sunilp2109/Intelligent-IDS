from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AnalysisThresholds:
    """Initial heuristic thresholds for behavioral attack analysis.

    These values are development defaults based on the current honeypot feature
    ranges. They are not universally correct and must be validated experimentally.
    """

    high_login_attempts: int = 10
    high_failed_count: int = 8
    high_failed_ratio: float = 0.75
    high_attempts_per_minute: float = 10.0
    high_command_rate: float = 6.0
    high_event_frequency: float = 12.0
    repeated_auth_min_attempts: int = 5
    repeated_command_threshold: int = 2
    brute_force_min_attempts: int = 8
    brute_force_min_failed: int = 6
    brute_force_min_failed_ratio: float = 0.70
    min_duration_for_rate_seconds: float = 5.0
    min_events_for_frequency: int = 6
    min_commands_for_rate: int = 3
    multiple_username_threshold: int = 3
    multiple_source_ip_threshold: int = 2
    unauthorized_min_failures: int = 3
    unauthorized_min_attempts: int = 4
    short_duration_max_seconds: float = 30.0
    short_duration_min_events: int = 10
    low_ml_confidence: float = 0.50

    def to_dict(self) -> dict[str, float | int]:
        return asdict(self)


DEFAULT_THRESHOLDS = AnalysisThresholds()
