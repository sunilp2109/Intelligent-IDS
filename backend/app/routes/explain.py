from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import ExplainRequest, ExplainResponse
from app.services.explain import run_explanation
from ml.explainability.shap_explainer import (
    ExplanationError,
    ExplanationUnavailableError,
)
from ml.models.predict import InvalidFeatureInputError

router = APIRouter(prefix="/api", tags=["explainability"])


@router.post("/explain", response_model=ExplainResponse)
def explain_prediction(
    payload: ExplainRequest,
    db: Session = Depends(get_db),
) -> ExplainResponse:
    features = payload.model_dump(exclude={"log_id", "detection_id", "top_features"})
    try:
        result, _record = run_explanation(
            db,
            features,
            log_id=payload.log_id,
            detection_id=payload.detection_id,
            top_n=payload.top_features,
        )
    except ExplanationUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except InvalidFeatureInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ExplanationError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    return ExplainResponse(**result)
