from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AttackAnalysis, AttackLog, Detection, RiskAssessment
from app.services.analysis import analyze_detection
from ml.risk.engine import assess_risk


def persist_risk_assessment(
    db: Session,
    result: dict[str, Any],
    *,
    detection_id: int | None = None,
) -> RiskAssessment:
    record = RiskAssessment(
        detection_id=detection_id,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        recommended_action=result["recommended_action"],
        operator_guidance=result["operator_guidance"],
        execution_status=result["execution_status"],
        decision_reason=result["decision_reason"],
        risk_breakdown=result["risk_breakdown"],
        overrides_applied=result["overrides_applied"],
        inputs_snapshot={
            "classification": result["classification"],
            "ml_confidence": result["ml_confidence"],
            "attack_category": result["attack_category"],
            "indicators": result["indicators"],
            "evidence_strength": result["evidence_strength"],
        },
    )
    db.add(record)
    if detection_id is not None:
        detection = db.get(Detection, detection_id)
        if detection is not None and detection.attack_log_id is not None:
            attack_log = db.get(AttackLog, detection.attack_log_id)
            if attack_log is not None:
                attack_log.risk_level = result["risk_level"]
    db.commit()
    db.refresh(record)
    return record


def assess_from_payload(
    *,
    classification: str,
    confidence_score: float,
    attack_category: str,
    evidence_strength: str,
    features: dict[str, Any],
    indicators: list[str] | None = None,
) -> dict[str, Any]:
    return assess_risk(
        classification=classification,
        confidence_score=confidence_score,
        attack_category=attack_category,
        evidence_strength=evidence_strength,
        features=features,
        indicators=indicators,
    )


def _latest_analysis(db: Session, detection_id: int) -> AttackAnalysis | None:
    statement = (
        select(AttackAnalysis)
        .where(AttackAnalysis.detection_id == detection_id)
        .order_by(AttackAnalysis.id.desc())
    )
    return db.scalars(statement).first()


def assess_detection(db: Session, detection_id: int) -> dict[str, Any]:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise LookupError(f"Detection {detection_id} was not found.")
    analysis = _latest_analysis(db, detection_id)
    if analysis is None:
        if detection.attack_log_id is None:
            raise ValueError(
                "This detection has no AttackAnalysis and no linked AttackLog. "
                "POST /api/risk/assess with explicit analysis fields, or POST /api/analysis/analyze first."
            )
        analyzed = analyze_detection(db, detection_id)
        features = analyzed["features"]
        category = analyzed["attack_category"]
        indicators = analyzed["indicators"]
        strength = analyzed["evidence_strength"]
        analysis_id = analyzed.get("analysis_id")
    else:
        features = analysis.features
        if not features:
            raise ValueError("Stored analysis has no feature vector to score.")
        category = analysis.attack_category
        indicators = list(analysis.indicators or [])
        strength = analysis.evidence_strength
        analysis_id = analysis.id
    result = assess_from_payload(
        classification=detection.classification,
        confidence_score=detection.confidence_score,
        attack_category=category,
        evidence_strength=strength,
        features=features,
        indicators=indicators,
    )
    saved = persist_risk_assessment(db, result, detection_id=detection.id)
    result["risk_id"] = saved.id
    result["detection_id"] = detection.id
    result["analysis_id"] = analysis_id
    result["attack_log_id"] = detection.attack_log_id
    return result
