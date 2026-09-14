from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.dashboard import (
    attack_distribution,
    dashboard_stats,
    dashboard_timeline,
    event_detail,
    list_activity_logs,
    list_alerts,
    recent_events,
    risk_distribution,
    system_status,
)

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)) -> dict:
    return dashboard_stats(db)


@router.get("/dashboard/timeline")
def get_dashboard_timeline(
    days: int = Query(default=14, ge=1, le=90),
    db: Session = Depends(get_db),
) -> list[dict]:
    return dashboard_timeline(db, days=days)


@router.get("/dashboard/attacks")
def get_attack_distribution(db: Session = Depends(get_db)) -> list[dict]:
    return attack_distribution(db)


@router.get("/dashboard/risks")
def get_risk_distribution(db: Session = Depends(get_db)) -> list[dict]:
    return risk_distribution(db)


@router.get("/dashboard/recent")
def get_recent_events(
    limit: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[dict]:
    return recent_events(db, limit=limit)


@router.get("/dashboard/alerts")
def get_dashboard_alerts(
    levels: str | None = Query(default="HIGH,CRITICAL"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[dict]:
    parsed = [item.strip() for item in (levels or "").split(",") if item.strip()]
    return list_alerts(db, levels=parsed or None, limit=limit)


@router.get("/dashboard/logs")
def get_dashboard_logs(
    source_ip: str | None = None,
    risk_level: str | None = None,
    classification: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    return list_activity_logs(
        db,
        source_ip=source_ip,
        risk_level=risk_level,
        classification=classification,
        limit=limit,
        offset=offset,
    )


@router.get("/dashboard/events/{detection_id}")
def get_dashboard_event(
    detection_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return event_detail(db, detection_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/system/status")
def get_system_status(db: Session = Depends(get_db)) -> dict:
    return system_status(db)
