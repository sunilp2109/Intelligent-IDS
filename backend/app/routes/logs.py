from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AttackLog
from app.schemas import AttackLogCreate, AttackLogResponse

router = APIRouter(prefix="/api/logs", tags=["logs"])


def _get_log_or_404(db: Session, log_id: int) -> AttackLog:
    log = db.get(AttackLog, log_id)
    if log is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack log {log_id} was not found.",
        )
    return log


@router.post(
    "",
    response_model=AttackLogResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_log(payload: AttackLogCreate, db: Session = Depends(get_db)) -> AttackLog:
    log = AttackLog(
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        ip_address=payload.ip_address,
        attempts=payload.attempts,
        commands=payload.commands,
        status=payload.status,
        risk_level=payload.risk_level,
    )
    db.add(log)
    try:
        db.commit()
        db.refresh(log)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The attack log could not be saved.",
        )
    return log


@router.get("", response_model=list[AttackLogResponse])
def list_logs(db: Session = Depends(get_db)) -> list[AttackLog]:
    try:
        statement = select(AttackLog).order_by(AttackLog.id.desc())
        return list(db.scalars(statement).all())
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Attack logs could not be retrieved.",
        )


@router.get("/{log_id}", response_model=AttackLogResponse)
def get_log(
    log_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> AttackLog:
    return _get_log_or_404(db, log_id)


@router.delete("/{log_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_log(
    log_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> None:
    log = _get_log_or_404(db, log_id)
    try:
        db.delete(log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The attack log could not be deleted.",
        )
