from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ml.analysis.analyzer import ATTACK_CATEGORIES, ML_CLASSES

# Initial project heuristics. Not a calibrated probability of harm and not a
# universal cybersecurity standard. Change values here, not in the scorer.


@dataclass(frozen=True)
class RiskConfig:
    """Central weights and thresholds for Module 7 risk scoring.

    Component maxima sum to 100 so the unadjusted score is already on a 0–100
    scale. Each weight is a development default and must be treated as tunable.
    """

    classification_max: float = 30.0
    confidence_max: float = 20.0
    attack_category_max: float = 25.0
    behavior_max: float = 15.0
    evidence_max: float = 10.0

    classification_weights: dict[str, float] = field(
        default_factory=lambda: {
            # Normal sessions should not accumulate classification risk.
            "normal": 0.0,
            # Suspicious is a real detector concern but not a confirmed attack class.
            "suspicious": 15.0,
            # Malicious is the strongest detector signal; still only 30/100 of the score.
            "malicious": 30.0,
        }
    )
    # Scales confidence_max * ml_confidence. Confidence that a session is normal
    # must not add risk. Low-confidence malicious still stays malicious.
    confidence_scale: dict[str, float] = field(
        default_factory=lambda: {
            "normal": 0.0,
            "suspicious": 0.70,
            "malicious": 1.0,
        }
    )
    attack_category_weights: dict[str, float] = field(
        default_factory=lambda: {
            "NORMAL_ACTIVITY": 0.0,
            "REPEATED_AUTHENTICATION_ATTEMPTS": 10.0,
            "ABNORMAL_REQUEST_ACTIVITY": 12.0,
            # Unknown is not the lowest: Module 5 only uses it when ML is already
            # suspicious/malicious but no named pattern matched.
            "UNKNOWN_SUSPICIOUS_ACTIVITY": 14.0,
            "SUSPICIOUS_COMMAND_ACTIVITY": 16.0,
            "BRUTE_FORCE": 20.0,
            # Successful login after failures is treated as the most severe
            # honeypot behavior currently modeled.
            "UNAUTHORIZED_ACCESS_ATTEMPT": 25.0,
        }
    )
    evidence_weights: dict[str, float] = field(
        default_factory=lambda: {
            "LOW": 2.0,
            "MEDIUM": 6.0,
            "HIGH": 10.0,
        }
    )
    indicator_weights: dict[str, float] = field(
        default_factory=lambda: {
            "HIGH_LOGIN_ATTEMPTS": 1.0,
            "HIGH_FAILED_LOGIN_COUNT": 1.5,
            "HIGH_FAILED_LOGIN_RATIO": 2.0,
            "HIGH_LOGIN_ATTEMPT_RATE": 2.0,
            "REPEATED_AUTHENTICATION_ATTEMPTS": 1.0,
            "HIGH_COMMAND_RATE": 1.5,
            "REPEATED_COMMANDS": 1.0,
            "SUSPICIOUS_COMMAND_PATTERN": 2.5,
            "MULTIPLE_USERNAMES": 1.0,
            "MULTIPLE_SOURCE_IPS": 1.0,
            "HIGH_EVENT_FREQUENCY": 1.5,
            "SHORT_DURATION_HIGH_VOLUME": 1.5,
        }
    )
    failed_ratio_points: float = 3.0
    min_logins_for_ratio_points: float = 3.0
    min_duration_for_rate_seconds: float = 5.0
    attempts_per_minute_cap: float = 20.0
    attempt_rate_points: float = 2.0
    commands_per_minute_cap: float = 12.0
    command_rate_points: float = 1.5
    events_per_minute_cap: float = 24.0
    event_rate_points: float = 1.5
    indicator_points_cap: float = 10.0

    low_max: float = 24.0
    medium_max: float = 49.0
    high_max: float = 74.0
    low_confidence: float = 0.50
    normal_default_cap: float = 24.0
    normal_strong_evidence_cap: float = 49.0
    low_confidence_suspicious_cap: float = 74.0
    low_confidence_weak_malicious_cap: float = 74.0

    def to_dict(self) -> dict:
        return asdict(self)


DEFAULT_RISK_CONFIG = RiskConfig()

VALID_CLASSIFICATIONS = ML_CLASSES
VALID_CATEGORIES = frozenset(ATTACK_CATEGORIES)
VALID_EVIDENCE_STRENGTH = frozenset({"LOW", "MEDIUM", "HIGH"})
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
RECOMMENDED_ACTIONS = ("ALLOW", "ALERT", "BLOCK")
