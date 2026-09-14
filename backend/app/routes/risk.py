from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Detection
from app.schemas import RiskAssessRequest, RiskAssessResponse
from app.services.risk import assess_detection, assess_from_payload, persist_risk_assessment
from ml.risk.config import DEFAULT_RISK_CONFIG
from ml.risk.scorer import RiskInputError

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("/thresholds")
def get_risk_thresholds() -> dict:
    payload = DEFAULT_RISK_CONFIG.to_dict()
    payload["note"] = (
        "These are initial development heuristics for a 0–100 risk score. "
        "They are not a probability of attack and are not universally validated."
    )
    payload["action_note"] = "BLOCK is a recommendation only; this API does not modify firewalls."
    return payload


@router.post("/assess", response_model=RiskAssessResponse)
def assess_activity(
    payload: RiskAssessRequest,
    db: Session = Depends(get_db),
) -> RiskAssessResponse:
    features = payload.model_dump(
        exclude={
            "classification",
            "confidence_score",
            "attack_category",
            "indicators",
            "evidence_strength",
            "detection_id",
        }
    )
    try:
        result = assess_from_payload(
            classification=payload.classification,
            confidence_score=payload.confidence_score,
            attack_category=payload.attack_category,
            evidence_strength=payload.evidence_strength,
            features=features,
            indicators=payload.indicators,
        )
        if payload.detection_id is not None:
            detection = db.get(Detection, payload.detection_id)
            if detection is None:
                raise LookupError(f"Detection {payload.detection_id} was not found.")
            saved = persist_risk_assessment(db, result, detection_id=detection.id)
            result["risk_id"] = saved.id
            result["detection_id"] = detection.id
    except RiskInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return RiskAssessResponse(**result)


@router.get("/{detection_id}", response_model=RiskAssessResponse)
def assess_existing_detection(
    detection_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> RiskAssessResponse:
    try:
        result = assess_detection(db, detection_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RiskInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return RiskAssessResponse(**result)
