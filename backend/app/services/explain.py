from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import Detection
from app.services.detection import persist_detection
from ml.explainability.shap_explainer import explain_features


def store_explanation(db: Session, detection_id: int, explanation: dict[str, Any]) -> Detection:
    record = db.get(Detection, detection_id)
    if record is None:
        raise LookupError(f"Detection {detection_id} was not found.")
    record.explanation = explanation
    db.commit()
    db.refresh(record)
    return record


def run_explanation(
    db: Session,
    features: dict[str, Any],
    *,
    log_id: int | None = None,
    detection_id: int | None = None,
    top_n: int = 5,
) -> tuple[dict[str, Any], Detection | None]:
    result = explain_features(features, top_n=top_n)
    record = None
    if detection_id is not None:
        record = store_explanation(db, detection_id, result["explanation"])
        result["detection_id"] = record.id
        return result, record
    if log_id is not None:
        record = persist_detection(
            db,
            classification=result["classification"],
            confidence_score=result["confidence_score"],
            log_id=log_id,
            explanation=result["explanation"],
        )
        result["detection_id"] = record.id
        return result, record
    result["detection_id"] = None
    return result, None
