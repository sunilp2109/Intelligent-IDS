from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Detection
from app.schemas import AnalysisRequest, AnalysisResponse
from app.services.analysis import analyze_detection, analyze_from_payload, persist_analysis
from ml.analysis.analyzer import AnalysisInputError
from ml.analysis.thresholds import DEFAULT_THRESHOLDS

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


@router.get("/thresholds")
def get_analysis_thresholds() -> dict:
    payload = DEFAULT_THRESHOLDS.to_dict()
    payload["note"] = (
        "These are initial development heuristics, not universally validated IDS thresholds."
    )
    return payload


@router.post("/analyze", response_model=AnalysisResponse)
def analyze_features(
    payload: AnalysisRequest,
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    features = payload.model_dump(exclude={"classification", "confidence_score", "detection_id"})
    try:
        result = analyze_from_payload(
            features,
            classification=payload.classification,
            confidence_score=payload.confidence_score,
        )
        if payload.detection_id is not None:
            detection = db.get(Detection, payload.detection_id)
            if detection is None:
                raise LookupError(f"Detection {payload.detection_id} was not found.")
            saved = persist_analysis(db, result, detection_id=detection.id)
            result["analysis_id"] = saved.id
            result["detection_id"] = detection.id
    except AnalysisInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return AnalysisResponse(**result)


@router.get("/{detection_id}", response_model=AnalysisResponse)
def analyze_existing_detection(
    detection_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    try:
        result = analyze_detection(db, detection_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except AnalysisInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return AnalysisResponse(**result)
