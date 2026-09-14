from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Detection
from app.schemas import DetectionPredictRequest, DetectionPredictResponse, DetectionRecord
from app.services.detection import run_detection
from ml.models.model_registry import load_registry
from ml.models.predict import InvalidFeatureInputError, ModelNotFoundError

router = APIRouter(prefix="/api/detection", tags=["detection"])


@router.post("/predict", response_model=DetectionPredictResponse)
def predict_detection(
    payload: DetectionPredictRequest,
    db: Session = Depends(get_db),
) -> DetectionPredictResponse:
    features = payload.model_dump(exclude={"log_id"})
    try:
        prediction, _record = run_detection(db, features, log_id=payload.log_id)
    except ModelNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except InvalidFeatureInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return DetectionPredictResponse(**prediction)


@router.get("/model")
def detection_model_info() -> dict[str, Any]:
    registry = load_registry()
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No trained model is available. Train one first with: python -m ml.models.train",
        )
    return registry.to_dict()


@router.get("/{detection_id}", response_model=DetectionRecord)
def get_detection(
    detection_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> Detection:
    record = db.get(Detection, detection_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} was not found.",
        )
    return record
