from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import PROJECT_ROOT
from app.database import get_db
from app.models import AttackLog
from app.schemas import (
    HoneypotEventIn,
    ImportReportResponse,
    ImportRequest,
    IngestEventResponse,
)
from app.services.ingestion import import_jsonl_file
from app.services.pipeline import process_security_event, run_session_pipeline
from honeypot.parser.log_parser import normalize_event_payload

router = APIRouter(prefix="/api/collector", tags=["collector"])
DEFAULT_SAMPLE_LOG = PROJECT_ROOT / "honeypot" / "logs" / "sample_events.jsonl"


def _safe_project_file(path_value: str | None) -> Path:
    raw_path = Path(path_value) if path_value else DEFAULT_SAMPLE_LOG
    candidate = raw_path if raw_path.is_absolute() else (PROJECT_ROOT / raw_path)
    resolved = candidate.resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log path must be inside the project directory.",
        ) from exc
    if not resolved.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log file was not found: {resolved}",
        )
    return resolved


@router.post(
    "/events",
    response_model=IngestEventResponse,
    status_code=status.HTTP_200_OK,
)
def collect_event(payload: HoneypotEventIn, db: Session = Depends(get_db)) -> IngestEventResponse:
    try:
        event = normalize_event_payload(payload.model_dump())
        processed = process_security_event(db, event)
        outcome = processed.ingest
        attack_log = db.get(AttackLog, outcome.attack_log_id)
        if attack_log is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="The event was processed but the activity record was not found.",
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The honeypot event could not be stored.",
        ) from exc

    return IngestEventResponse(
        result=outcome.result,
        event_hash=outcome.event_hash,
        attack_log_id=outcome.attack_log_id,
        attack_log=attack_log,
    )


@router.post("/import", response_model=ImportReportResponse)
def import_events(
    payload: ImportRequest = ImportRequest(),
    db: Session = Depends(get_db),
) -> ImportReportResponse:
    log_path = _safe_project_file(payload.path)
    try:
        report = import_jsonl_file(db, log_path)
        for log_id in dict.fromkeys(report.inserted_log_ids):
            run_session_pipeline(db, log_id)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The honeypot log file could not be imported.",
        ) from exc
    return ImportReportResponse(**report.to_dict())
