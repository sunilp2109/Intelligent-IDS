from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import PROJECT_ROOT
from app.database import get_db
from app.schemas import FeatureExportResponse, FeatureExtractionResponse
from app.services.features import extract_features_from_db
from ml.preprocessing.feature_extractor import write_features_csv

router = APIRouter(prefix="/api/features", tags=["features"])
DEFAULT_EXPORT_PATH = PROJECT_ROOT / "ml" / "data" / "features.csv"


@router.get("", response_model=FeatureExtractionResponse)
def get_features(
    source_ip: str | None = Query(default=None),
    log_id: int | None = Query(default=None, ge=1),
    window_minutes: int | None = Query(default=None, ge=1, le=1440),
    db: Session = Depends(get_db),
) -> FeatureExtractionResponse:
    try:
        records = extract_features_from_db(
            db,
            source_ip=source_ip,
            log_id=log_id,
            window_minutes=window_minutes,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Behavioral features could not be calculated.",
        ) from exc
    grouping = "time_window" if window_minutes is not None else "attack_log"
    return FeatureExtractionResponse(
        count=len(records),
        grouping=grouping,
        feature_vectors=records,
    )


@router.post("/export", response_model=FeatureExportResponse)
def export_features(
    source_ip: str | None = Query(default=None),
    log_id: int | None = Query(default=None, ge=1),
    window_minutes: int | None = Query(default=None, ge=1, le=1440),
    db: Session = Depends(get_db),
) -> FeatureExportResponse:
    try:
        records = extract_features_from_db(
            db,
            source_ip=source_ip,
            log_id=log_id,
            window_minutes=window_minutes,
        )
        output = write_features_csv(records, DEFAULT_EXPORT_PATH)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Behavioral features could not be exported.",
        ) from exc
    return FeatureExportResponse(file=str(output), count=len(records))
