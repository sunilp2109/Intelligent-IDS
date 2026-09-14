from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AttackLog, Detection
from ml.models.predict import predict_features


def persist_detection(
    db: Session,
    *,
    classification: str,
    confidence_score: float,
    log_id: int | None = None,
    explanation: dict | None = None,
) -> Detection:
    if log_id is not None and db.get(AttackLog, log_id) is None:
        raise LookupError(f"Attack log {log_id} was not found.")
    record = Detection(
        attack_log_id=log_id,
        classification=classification,
        confidence_score=confidence_score,
        explanation=explanation,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def run_detection(db: Session, features: dict, log_id: int | None = None) -> tuple[dict, Detection | None]:
    prediction = predict_features(features)
    record = None
    if log_id is not None:
        record = persist_detection(
            db,
            classification=prediction["classification"],
            confidence_score=prediction["confidence_score"],
            log_id=log_id,
        )
        prediction["detection_id"] = record.id
    else:
        prediction["detection_id"] = None
    prediction["explanation"] = None
    return prediction, record
