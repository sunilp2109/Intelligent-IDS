from __future__ import annotations

from typing import Any

from ml.analysis.thresholds import DEFAULT_THRESHOLDS, AnalysisThresholds
from ml.preprocessing.feature_schema import FEATURE_NAMES

ML_CLASSES = frozenset({"normal", "suspicious", "malicious"})

ATTACK_CATEGORIES = (
    "BRUTE_FORCE",
    "REPEATED_AUTHENTICATION_ATTEMPTS",
    "SUSPICIOUS_COMMAND_ACTIVITY",
    "ABNORMAL_REQUEST_ACTIVITY",
    "UNAUTHORIZED_ACCESS_ATTEMPT",
    "UNKNOWN_SUSPICIOUS_ACTIVITY",
    "NORMAL_ACTIVITY",
)

CATEGORY_PRIORITY = (
    "BRUTE_FORCE",
    "UNAUTHORIZED_ACCESS_ATTEMPT",
    "SUSPICIOUS_COMMAND_ACTIVITY",
    "ABNORMAL_REQUEST_ACTIVITY",
    "REPEATED_AUTHENTICATION_ATTEMPTS",
)

INDICATOR_EVIDENCE: dict[str, tuple[str, ...]] = {
    "HIGH_LOGIN_ATTEMPTS": ("login_attempts",),
    "HIGH_FAILED_LOGIN_COUNT": ("failed_login_attempts",),
    "HIGH_FAILED_LOGIN_RATIO": ("failed_login_attempts", "login_attempts", "failed_login_ratio"),
    "HIGH_LOGIN_ATTEMPT_RATE": ("attempts_per_minute", "session_duration_seconds", "login_attempts"),
    "REPEATED_AUTHENTICATION_ATTEMPTS": ("login_attempts", "failed_login_attempts"),
    "HIGH_COMMAND_RATE": ("commands_per_minute", "command_count", "session_duration_seconds"),
    "REPEATED_COMMANDS": ("repeated_command_count", "command_count", "unique_command_count"),
    "SUSPICIOUS_COMMAND_PATTERN": ("suspicious_command_indicator", "command_count"),
    "MULTIPLE_USERNAMES": ("unique_username_count",),
    "MULTIPLE_SOURCE_IPS": ("unique_source_ip_count",),
    "HIGH_EVENT_FREQUENCY": ("events_per_minute", "total_events", "session_duration_seconds"),
    "SHORT_DURATION_HIGH_VOLUME": ("session_duration_seconds", "total_events", "events_per_minute"),
}


class AnalysisInputError(ValueError):
    pass


def _require_prediction(ml_prediction: dict[str, Any] | None) -> tuple[str, float]:
    if not ml_prediction:
        raise AnalysisInputError("ML prediction is missing.")
    if "classification" not in ml_prediction or ml_prediction["classification"] in (None, ""):
        raise AnalysisInputError("ML prediction is missing classification.")
    if "confidence_score" not in ml_prediction or ml_prediction["confidence_score"] is None:
        raise AnalysisInputError("ML prediction is missing confidence_score.")
    classification = str(ml_prediction["classification"]).strip().lower()
    if classification not in ML_CLASSES:
        raise AnalysisInputError("ML classification must be normal, suspicious, or malicious.")
    try:
        confidence = float(ml_prediction["confidence_score"])
    except (TypeError, ValueError) as exc:
        raise AnalysisInputError("ML confidence_score must be numeric.") from exc
    if confidence != confidence or confidence < 0 or confidence > 1:
        raise AnalysisInputError("ML confidence_score must be between 0 and 1.")
    return classification, confidence


def _numeric_features(features: dict[str, Any] | None) -> dict[str, float]:
    if not features:
        raise AnalysisInputError("Feature vector is missing.")
    missing = [name for name in FEATURE_NAMES if name not in features]
    if missing:
        raise AnalysisInputError(f"Missing required feature(s): {', '.join(missing)}")
    cleaned: dict[str, float] = {}
    for name in FEATURE_NAMES:
        try:
            value = float(features[name])
        except (TypeError, ValueError) as exc:
            raise AnalysisInputError(f"Feature {name} must be numeric.") from exc
        if value != value:
            raise AnalysisInputError(f"Feature {name} is NaN.")
        cleaned[name] = value
    return cleaned


def _rate_is_usable(features: dict[str, float], thresholds: AnalysisThresholds) -> bool:
    return features["session_duration_seconds"] >= thresholds.min_duration_for_rate_seconds


def collect_indicators(features: dict[str, float], thresholds: AnalysisThresholds) -> list[str]:
    indicators: list[str] = []
    if features["login_attempts"] >= thresholds.high_login_attempts:
        indicators.append("HIGH_LOGIN_ATTEMPTS")
    if features["failed_login_attempts"] >= thresholds.high_failed_count:
        indicators.append("HIGH_FAILED_LOGIN_COUNT")
    if (
        features["login_attempts"] >= thresholds.repeated_auth_min_attempts
        and features["failed_login_ratio"] >= thresholds.high_failed_ratio
    ):
        indicators.append("HIGH_FAILED_LOGIN_RATIO")
    if _rate_is_usable(features, thresholds) and features["attempts_per_minute"] >= thresholds.high_attempts_per_minute:
        indicators.append("HIGH_LOGIN_ATTEMPT_RATE")
    if features["login_attempts"] >= thresholds.repeated_auth_min_attempts:
        indicators.append("REPEATED_AUTHENTICATION_ATTEMPTS")
    if (
        features["command_count"] >= thresholds.min_commands_for_rate
        and _rate_is_usable(features, thresholds)
        and features["commands_per_minute"] >= thresholds.high_command_rate
    ):
        indicators.append("HIGH_COMMAND_RATE")
    if features["repeated_command_count"] >= thresholds.repeated_command_threshold:
        indicators.append("REPEATED_COMMANDS")
    if features["suspicious_command_indicator"] >= 1:
        indicators.append("SUSPICIOUS_COMMAND_PATTERN")
    if features["unique_username_count"] >= thresholds.multiple_username_threshold:
        indicators.append("MULTIPLE_USERNAMES")
    if features["unique_source_ip_count"] >= thresholds.multiple_source_ip_threshold:
        indicators.append("MULTIPLE_SOURCE_IPS")
    if (
        features["total_events"] >= thresholds.min_events_for_frequency
        and _rate_is_usable(features, thresholds)
        and features["events_per_minute"] >= thresholds.high_event_frequency
    ):
        indicators.append("HIGH_EVENT_FREQUENCY")
    if (
        features["session_duration_seconds"] <= thresholds.short_duration_max_seconds
        and features["total_events"] >= thresholds.short_duration_min_events
    ):
        indicators.append("SHORT_DURATION_HIGH_VOLUME")
    return indicators


def match_categories(features: dict[str, float], indicators: list[str], thresholds: AnalysisThresholds) -> list[str]:
    matched: list[str] = []
    brute_force = (
        features["login_attempts"] >= thresholds.brute_force_min_attempts
        and features["failed_login_attempts"] >= thresholds.brute_force_min_failed
        and features["failed_login_ratio"] >= thresholds.brute_force_min_failed_ratio
    )
    if brute_force:
        matched.append("BRUTE_FORCE")
    if features["login_attempts"] >= thresholds.repeated_auth_min_attempts:
        matched.append("REPEATED_AUTHENTICATION_ATTEMPTS")
    if (
        "SUSPICIOUS_COMMAND_PATTERN" in indicators
        or "REPEATED_COMMANDS" in indicators
        or "HIGH_COMMAND_RATE" in indicators
    ):
        matched.append("SUSPICIOUS_COMMAND_ACTIVITY")
    if "HIGH_EVENT_FREQUENCY" in indicators or "SHORT_DURATION_HIGH_VOLUME" in indicators:
        matched.append("ABNORMAL_REQUEST_ACTIVITY")
    unauthorized = (
        features["successful_login_attempts"] >= 1
        and features["failed_login_attempts"] >= thresholds.unauthorized_min_failures
        and features["login_attempts"] >= thresholds.unauthorized_min_attempts
    )
    if unauthorized:
        matched.append("UNAUTHORIZED_ACCESS_ATTEMPT")
    order = {name: index for index, name in enumerate(CATEGORY_PRIORITY)}
    return sorted(dict.fromkeys(matched), key=lambda name: order.get(name, 99))


def _evidence_for(features: dict[str, float], indicators: list[str], categories: list[str]) -> dict[str, float]:
    keys: list[str] = []
    for indicator in indicators:
        keys.extend(INDICATOR_EVIDENCE.get(indicator, ()))
    if "BRUTE_FORCE" in categories:
        keys.extend(
            (
                "login_attempts",
                "failed_login_attempts",
                "successful_login_attempts",
                "failed_login_ratio",
                "attempts_per_minute",
            )
        )
    if "SUSPICIOUS_COMMAND_ACTIVITY" in categories:
        keys.extend(("command_count", "repeated_command_count", "suspicious_command_indicator"))
    unique_keys = list(dict.fromkeys(keys))
    return {name: features[name] for name in unique_keys if name in features}


def _evidence_strength(indicators: list[str], categories: list[str], features: dict[str, float]) -> str:
    count = len(indicators)
    brute_force_strong = (
        "BRUTE_FORCE" in categories
        and features["login_attempts"] >= 15
        and features["failed_login_ratio"] >= 0.85
    )
    if brute_force_strong or count >= 4:
        return "HIGH"
    if count >= 2 or categories:
        return "MEDIUM"
    return "LOW"


def analyze_activity(
    features: dict[str, Any] | None,
    ml_prediction: dict[str, Any] | None,
    *,
    thresholds: AnalysisThresholds = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    """Interpret behavioral evidence. Does not change the ML classification."""
    cleaned = _numeric_features(features)
    classification, ml_confidence = _require_prediction(ml_prediction)
    indicators = collect_indicators(cleaned, thresholds)
    matched_categories = match_categories(cleaned, indicators, thresholds)

    insufficient_reason = None
    secondary: list[str] = []
    if classification == "normal":
        primary = "NORMAL_ACTIVITY"
        if not matched_categories:
            indicators = []
        else:
            secondary = matched_categories
    elif not matched_categories:
        primary = "UNKNOWN_SUSPICIOUS_ACTIVITY"
        insufficient_reason = (
            f"ML classified the activity as {classification}, but no supported "
            "behavioral category rule matched the observed feature values."
        )
    else:
        primary = matched_categories[0]
        secondary = matched_categories[1:]

    evidence = _evidence_for(cleaned, indicators, [primary, *secondary])
    return {
        "classification": classification,
        "ml_confidence": ml_confidence,
        "ml_confidence_low": ml_confidence < thresholds.low_ml_confidence,
        "attack_category": primary,
        "primary_category": primary,
        "secondary_categories": secondary,
        "indicators": indicators,
        "evidence": evidence,
        "evidence_strength": _evidence_strength(indicators, matched_categories, cleaned),
        "insufficient_evidence_reason": insufficient_reason,
        "features": cleaned,
        "feature_names": list(FEATURE_NAMES),
        "analysis_type": "behavioral_heuristic",
        "notes": "Attack category is a behavioral interpretation, not an ML prediction.",
    }
