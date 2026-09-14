from __future__ import annotations

from typing import Any

from ml.risk.config import DEFAULT_RISK_CONFIG, RiskConfig
from ml.risk.decisions import build_decision_reason, recommend_action
from ml.risk.scorer import score_risk, validate_risk_inputs


def assess_risk(
    *,
    classification: Any,
    confidence_score: Any,
    attack_category: Any,
    evidence_strength: Any,
    features: dict[str, Any] | None,
    indicators: list[str] | None = None,
    config: RiskConfig = DEFAULT_RISK_CONFIG,
) -> dict[str, Any]:
    """Turn Module 4–5 outputs into a risk score and a recommended action.

    Does not run ML, SHAP, or feature extraction. Does not block anything.
    """
    payload = validate_risk_inputs(
        classification=classification,
        confidence_score=confidence_score,
        attack_category=attack_category,
        evidence_strength=evidence_strength,
        features=features,
        indicators=indicators,
    )
    scored = score_risk(payload, config)
    decision = recommend_action(scored["risk_level"])
    reasons = build_decision_reason(payload, scored, decision)
    return {
        "classification": payload["classification"],
        "ml_confidence": payload["confidence_score"],
        "attack_category": payload["attack_category"],
        "indicators": payload["indicators"],
        "evidence_strength": payload["evidence_strength"],
        "features": payload["features"],
        "risk_score": scored["risk_score"],
        "risk_level": scored["risk_level"],
        "recommended_action": decision["recommended_action"],
        "operator_guidance": decision["operator_guidance"],
        "execution_status": decision["execution_status"],
        "risk_breakdown": scored["risk_breakdown"],
        "decision_reason": reasons,
        "overrides_applied": scored["overrides_applied"],
        "notes": (
            "Risk score is a transparent 0–100 heuristic, not a probability of attack. "
            "BLOCK is a recommendation only."
        ),
        "action_is_recommendation": True,
    }
