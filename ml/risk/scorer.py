from __future__ import annotations

from typing import Any

from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.risk.config import (
    DEFAULT_RISK_CONFIG,
    VALID_CATEGORIES,
    VALID_CLASSIFICATIONS,
    VALID_EVIDENCE_STRENGTH,
    RiskConfig,
)


class RiskInputError(ValueError):
    pass


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def validate_risk_inputs(
    *,
    classification: Any,
    confidence_score: Any,
    attack_category: Any,
    evidence_strength: Any,
    features: dict[str, Any] | None,
    indicators: list[str] | None = None,
) -> dict[str, Any]:
    if classification in (None, ""):
        raise RiskInputError("classification is required.")
    class_name = str(classification).strip().lower()
    if class_name not in VALID_CLASSIFICATIONS:
        raise RiskInputError("classification must be normal, suspicious, or malicious.")
    try:
        confidence = float(confidence_score)
    except (TypeError, ValueError) as exc:
        raise RiskInputError("confidence_score must be numeric.") from exc
    if confidence != confidence or confidence < 0 or confidence > 1:
        raise RiskInputError("confidence_score must be between 0 and 1.")
    if attack_category in (None, ""):
        raise RiskInputError("attack_category is required.")
    category = str(attack_category).strip().upper()
    if category not in VALID_CATEGORIES:
        raise RiskInputError(f"attack_category must be one of: {', '.join(sorted(VALID_CATEGORIES))}.")
    if evidence_strength in (None, ""):
        raise RiskInputError("evidence_strength is required.")
    strength = str(evidence_strength).strip().upper()
    if strength not in VALID_EVIDENCE_STRENGTH:
        raise RiskInputError("evidence_strength must be LOW, MEDIUM, or HIGH.")
    if not features:
        raise RiskInputError("Feature vector is missing.")
    missing = [name for name in FEATURE_NAMES if name not in features]
    if missing:
        raise RiskInputError(f"Missing required feature(s): {', '.join(missing)}")
    cleaned_features: dict[str, float] = {}
    for name in FEATURE_NAMES:
        try:
            value = float(features[name])
        except (TypeError, ValueError) as exc:
            raise RiskInputError(f"Feature {name} must be numeric.") from exc
        if value != value:
            raise RiskInputError(f"Feature {name} is NaN.")
        cleaned_features[name] = value
    cleaned_indicators: list[str] = []
    for item in indicators or []:
        label = str(item).strip()
        if label:
            cleaned_indicators.append(label)
    return {
        "classification": class_name,
        "confidence_score": confidence,
        "attack_category": category,
        "evidence_strength": strength,
        "features": cleaned_features,
        "indicators": cleaned_indicators,
    }


def classification_component(classification: str, config: RiskConfig) -> float:
    return float(config.classification_weights.get(classification, 0.0))


def confidence_component(classification: str, confidence: float, config: RiskConfig) -> float:
    """Confidence scales risk for the predicted class. It never changes the class."""
    scale = float(config.confidence_scale.get(classification, 0.0))
    return round(config.confidence_max * confidence * scale, 4)


def attack_category_component(category: str, config: RiskConfig) -> float:
    return float(config.attack_category_weights.get(category, 0.0))


def evidence_component(classification: str, category: str, strength: str, config: RiskConfig) -> float:
    if classification == "normal" and category == "NORMAL_ACTIVITY":
        return 0.0
    return float(config.evidence_weights.get(strength, 0.0))


def behavior_component(
    features: dict[str, float],
    indicators: list[str],
    config: RiskConfig,
) -> float:
    """Uses Module 3 feature values and Module 5 indicators. Does not re-extract features."""
    indicator_points = 0.0
    for name in indicators:
        indicator_points += float(config.indicator_weights.get(name, 0.0))
    indicator_points = min(indicator_points, config.indicator_points_cap)

    ratio_points = 0.0
    if features["login_attempts"] >= config.min_logins_for_ratio_points:
        ratio_points = _clamp(features["failed_login_ratio"], 0.0, 1.0) * config.failed_ratio_points

    attempt_rate_points = 0.0
    command_rate_points = 0.0
    event_rate_points = 0.0
    if features["session_duration_seconds"] >= config.min_duration_for_rate_seconds:
        attempt_rate_points = (
            min(max(features["attempts_per_minute"], 0.0) / config.attempts_per_minute_cap, 1.0)
            * config.attempt_rate_points
        )
        command_rate_points = (
            min(max(features["commands_per_minute"], 0.0) / config.commands_per_minute_cap, 1.0)
            * config.command_rate_points
        )
        event_rate_points = (
            min(max(features["events_per_minute"], 0.0) / config.events_per_minute_cap, 1.0)
            * config.event_rate_points
        )
    total = (
        indicator_points
        + ratio_points
        + attempt_rate_points
        + command_rate_points
        + event_rate_points
    )
    return round(min(total, config.behavior_max), 4)


def get_risk_level(score: float, config: RiskConfig = DEFAULT_RISK_CONFIG) -> str:
    value = _clamp(float(score), 0.0, 100.0)
    if value <= config.low_max:
        return "LOW"
    if value <= config.medium_max:
        return "MEDIUM"
    if value <= config.high_max:
        return "HIGH"
    return "CRITICAL"


def apply_score_overrides(
    raw_score: float,
    *,
    classification: str,
    confidence: float,
    attack_category: str,
    evidence_strength: str,
    config: RiskConfig = DEFAULT_RISK_CONFIG,
) -> tuple[float, list[str]]:
    """Cap inflated scores. Does not rewrite the ML classification."""
    score = _clamp(raw_score, 0.0, 100.0)
    applied: list[str] = []
    if classification == "normal":
        strong_secondary = evidence_strength == "HIGH" and attack_category != "NORMAL_ACTIVITY"
        cap = config.normal_strong_evidence_cap if strong_secondary else config.normal_default_cap
        if score > cap:
            score = cap
            applied.append(
                "normal_classification_cap"
                if not strong_secondary
                else "normal_classification_strong_evidence_cap"
            )
    if classification == "suspicious" and confidence < config.low_confidence and score > config.low_confidence_suspicious_cap:
        score = config.low_confidence_suspicious_cap
        applied.append("low_confidence_suspicious_cap")
    weak_malicious = evidence_strength != "HIGH"
    if (
        classification == "malicious"
        and confidence < config.low_confidence
        and weak_malicious
        and score > config.low_confidence_weak_malicious_cap
    ):
        score = config.low_confidence_weak_malicious_cap
        applied.append("low_confidence_weak_malicious_cap")
    return score, applied


def score_risk(payload: dict[str, Any], config: RiskConfig = DEFAULT_RISK_CONFIG) -> dict[str, Any]:
    classification = payload["classification"]
    confidence = payload["confidence_score"]
    category = payload["attack_category"]
    strength = payload["evidence_strength"]
    components = {
        "classification": round(classification_component(classification, config), 2),
        "confidence": round(confidence_component(classification, confidence, config), 2),
        "attack_category": round(attack_category_component(category, config), 2),
        "behavior": round(behavior_component(payload["features"], payload["indicators"], config), 2),
        "evidence_strength": round(evidence_component(classification, category, strength, config), 2),
    }
    subtotal = round(sum(components.values()), 2)
    adjusted, overrides = apply_score_overrides(
        subtotal,
        classification=classification,
        confidence=confidence,
        attack_category=category,
        evidence_strength=strength,
        config=config,
    )
    risk_score = int(round(_clamp(adjusted, 0.0, 100.0)))
    components["override_adjustment"] = round(risk_score - subtotal, 2)
    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score, config),
        "risk_breakdown": components,
        "raw_subtotal": subtotal,
        "overrides_applied": overrides,
    }
