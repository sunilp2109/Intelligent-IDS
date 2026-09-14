from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import AttackAnalysis, Detection
from app.services.features import extract_features_from_db
from ml.analysis.analyzer import analyze_activity


def persist_analysis(
    db: Session,
    result: dict[str, Any],
    *,
    detection_id: int | None = None,
) -> AttackAnalysis:
    record = AttackAnalysis(
        detection_id=detection_id,
        attack_category=result["attack_category"],
        primary_indicator=result["indicators"][0] if result["indicators"] else result["attack_category"],
        indicators=result["indicators"],
        secondary_categories=result["secondary_categories"],
        evidence=result["evidence"],
        evidence_strength=result["evidence_strength"],
        features=result["features"],
        insufficient_evidence_reason=result["insufficient_evidence_reason"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def analyze_from_payload(
    features: dict[str, Any],
    *,
    classification: str,
    confidence_score: float,
) -> dict[str, Any]:
    return analyze_activity(
        features,
        {"classification": classification, "confidence_score": confidence_score},
    )


def analyze_detection(db: Session, detection_id: int) -> dict[str, Any]:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise LookupError(f"Detection {detection_id} was not found.")
    if detection.attack_log_id is None:
        raise ValueError(
            "This detection has no linked AttackLog, so features cannot be reconstructed. "
            "POST /api/analysis/analyze with an explicit feature vector."
        )
    records = extract_features_from_db(db, log_id=detection.attack_log_id)
    if not records:
        raise ValueError(
            "No honeypot events were found for this detection's AttackLog, so features cannot be calculated."
        )
    result = analyze_from_payload(
        records[0]["features"],
        classification=detection.classification,
        confidence_score=detection.confidence_score,
    )
    saved = persist_analysis(db, result, detection_id=detection.id)
    result["analysis_id"] = saved.id
    result["detection_id"] = detection.id
    result["attack_log_id"] = detection.attack_log_id
    return result
