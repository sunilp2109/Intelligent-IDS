from __future__ import annotations

from typing import Any


def recommend_action(risk_level: str) -> dict[str, str]:
    """Map a risk level to an operator recommendation. Never executes a block."""
    if risk_level == "LOW":
        action, guidance = "ALLOW", "MONITOR"
    elif risk_level == "MEDIUM":
        action, guidance = "ALERT", "MONITOR"
    elif risk_level == "HIGH":
        action, guidance = "ALERT", "INVESTIGATE"
    else:
        action, guidance = "BLOCK", "CONTAIN"
    return {
        "recommended_action": action,
        "operator_guidance": guidance,
        "execution_status": "recommendation_only",
    }


def build_decision_reason(payload: dict[str, Any], scored: dict[str, Any], decision: dict[str, str]) -> list[str]:
    """Explain the risk/response decision from actual inputs. Not a SHAP explanation."""
    classification = payload["classification"]
    confidence = payload["confidence_score"]
    category = payload["attack_category"]
    strength = payload["evidence_strength"]
    features = payload["features"]
    indicators = payload["indicators"]
    breakdown = scored["risk_breakdown"]
    reasons = [
        f"ML classified the activity as {classification}",
        f"Model confidence was {round(confidence * 100)}%",
        f"Behavioral category is {category}",
        f"Evidence strength is {strength}",
    ]
    if breakdown["classification"] > 0:
        reasons.append(
            f"Classification contributed {breakdown['classification']} points to the risk score"
        )
    if breakdown["confidence"] > 0:
        reasons.append(
            f"Confidence contributed {breakdown['confidence']} points to the risk score"
        )
    if breakdown["attack_category"] > 0:
        reasons.append(
            f"Attack category contributed {breakdown['attack_category']} points to the risk score"
        )
    if breakdown["behavior"] > 0:
        reasons.append(f"Behavioral evidence contributed {breakdown['behavior']} points to the risk score")
    if features["login_attempts"] >= 3 and features["failed_login_ratio"] >= 0.75:
        reasons.append(f"Failed-login ratio is {features['failed_login_ratio']:.2f}")
    if features["session_duration_seconds"] >= 5 and features["attempts_per_minute"] >= 10:
        reasons.append(f"Authentication frequency is {features['attempts_per_minute']:.1f} attempts/minute")
    if features["suspicious_command_indicator"] >= 1:
        reasons.append("Suspicious-command indicator is set")
    for indicator in indicators[:6]:
        reasons.append(f"Indicator present: {indicator}")
    for override in scored.get("overrides_applied") or []:
        if override == "normal_classification_cap":
            reasons.append("Score capped because ML classified the activity as normal")
        elif override == "normal_classification_strong_evidence_cap":
            reasons.append("Score capped at MEDIUM because ML classified the activity as normal")
        elif override == "low_confidence_suspicious_cap":
            reasons.append("Score capped so low-confidence suspicious activity cannot become CRITICAL")
        elif override == "low_confidence_weak_malicious_cap":
            reasons.append("Score capped because malicious confidence is low and evidence is not HIGH")
    reasons.append(
        f"Recommended action is {decision['recommended_action']} "
        f"({decision['operator_guidance']}); this is advisory only and does not block an IP"
    )
    return reasons
