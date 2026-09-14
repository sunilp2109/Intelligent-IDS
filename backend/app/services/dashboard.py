from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import DATABASE_URL
from app.models import AttackAnalysis, AttackLog, Detection, HoneypotEvent, RiskAssessment
from app.services.websocket_manager import get_connection_manager
from ml.models.config import model_path
from ml.models.model_registry import load_registry

SAMPLE_LOG = Path(__file__).resolve().parents[3] / "honeypot" / "logs" / "sample_events.jsonl"
ALERT_LEVELS = frozenset({"HIGH", "CRITICAL"})


def _latest_analysis_ids():
    return (
        select(func.max(AttackAnalysis.id).label("id"))
        .group_by(AttackAnalysis.detection_id)
        .subquery()
    )


def _latest_risk_ids():
    return (
        select(func.max(RiskAssessment.id).label("id"))
        .group_by(RiskAssessment.detection_id)
        .subquery()
    )


def _day_expr(column):
    return func.date(column)


def dashboard_stats(db: Session) -> dict[str, int]:
    total_events = int(db.scalar(select(func.count()).select_from(HoneypotEvent)) or 0)
    class_rows = db.execute(
        select(Detection.classification, func.count()).group_by(Detection.classification)
    ).all()
    counts = {"normal": 0, "suspicious": 0, "malicious": 0}
    for label, count in class_rows:
        key = str(label or "").strip().lower()
        if key in counts:
            counts[key] = int(count)
    latest_risk = _latest_risk_ids()
    critical = int(
        db.scalar(
            select(func.count())
            .select_from(RiskAssessment)
            .join(latest_risk, RiskAssessment.id == latest_risk.c.id)
            .where(RiskAssessment.risk_level == "CRITICAL")
        )
        or 0
    )
    active_alerts = int(
        db.scalar(
            select(func.count())
            .select_from(RiskAssessment)
            .join(latest_risk, RiskAssessment.id == latest_risk.c.id)
            .where(RiskAssessment.risk_level.in_(tuple(ALERT_LEVELS)))
        )
        or 0
    )
    return {
        "total_events": total_events,
        "normal": counts["normal"],
        "suspicious": counts["suspicious"],
        "malicious": counts["malicious"],
        "critical": critical,
        "active_alerts": active_alerts,
    }


def dashboard_timeline(db: Session, *, days: int = 14) -> list[dict[str, Any]]:
    event_count = int(db.scalar(select(func.count()).select_from(HoneypotEvent)) or 0)
    detection_count = int(db.scalar(select(func.count()).select_from(Detection)) or 0)
    if event_count == 0 and detection_count == 0:
        return []

    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=max(1, days) - 1)
    buckets = {
        (start + timedelta(days=offset)).isoformat(): {
            "timestamp": (start + timedelta(days=offset)).isoformat(),
            "events": 0,
            "normal": 0,
            "suspicious": 0,
            "malicious": 0,
        }
        for offset in range(max(1, days))
    }

    event_rows = db.execute(
        select(_day_expr(HoneypotEvent.timestamp), func.count()).group_by(_day_expr(HoneypotEvent.timestamp))
    ).all()
    for day, count in event_rows:
        key = str(day)
        if key in buckets:
            buckets[key]["events"] = int(count)

    class_rows = db.execute(
        select(_day_expr(Detection.created_at), Detection.classification, func.count()).group_by(
            _day_expr(Detection.created_at),
            Detection.classification,
        )
    ).all()
    for day, label, count in class_rows:
        key = str(day)
        class_name = str(label or "").strip().lower()
        if key in buckets and class_name in {"normal", "suspicious", "malicious"}:
            buckets[key][class_name] = int(count)
    return list(buckets.values())


def attack_distribution(db: Session) -> list[dict[str, Any]]:
    latest = _latest_analysis_ids()
    rows = db.execute(
        select(AttackAnalysis.attack_category, func.count())
        .join(latest, AttackAnalysis.id == latest.c.id)
        .where(AttackAnalysis.attack_category != "NORMAL_ACTIVITY")
        .group_by(AttackAnalysis.attack_category)
        .order_by(func.count().desc())
    ).all()
    return [{"category": str(category), "count": int(count)} for category, count in rows]


def risk_distribution(db: Session) -> list[dict[str, Any]]:
    latest = _latest_risk_ids()
    rows = db.execute(
        select(RiskAssessment.risk_level, func.count())
        .join(latest, RiskAssessment.id == latest.c.id)
        .group_by(RiskAssessment.risk_level)
    ).all()
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts = {level: 0 for level in order}
    for level, count in rows:
        key = str(level or "").upper()
        if key in counts:
            counts[key] = int(count)
    if sum(counts.values()) == 0:
        return []
    return [{"level": level, "count": counts[level]} for level in order]


def _serialize_event_row(
    detection: Detection,
    log: AttackLog | None,
    analysis: AttackAnalysis | None,
    risk: RiskAssessment | None,
) -> dict[str, Any]:
    timestamp = None
    if log is not None and log.timestamp is not None:
        timestamp = log.timestamp.isoformat()
    elif detection.created_at is not None:
        timestamp = detection.created_at.isoformat()
    return {
        "detection_id": detection.id,
        "attack_log_id": detection.attack_log_id,
        "timestamp": timestamp,
        "source_ip": log.ip_address if log is not None else None,
        "status": log.status if log is not None else None,
        "classification": detection.classification,
        "confidence_score": detection.confidence_score,
        "attack_category": analysis.attack_category if analysis is not None else None,
        "indicators": list(analysis.indicators or []) if analysis is not None else [],
        "evidence_strength": analysis.evidence_strength if analysis is not None else None,
        "risk_score": risk.risk_score if risk is not None else None,
        "risk_level": risk.risk_level if risk is not None else (log.risk_level if log is not None else None),
        "recommended_action": risk.recommended_action if risk is not None else None,
        "operator_guidance": risk.operator_guidance if risk is not None else None,
        "is_demo": (log.status or "").lower() == "demo" if log is not None else False,
    }


def recent_events(db: Session, *, limit: int = 20) -> list[dict[str, Any]]:
    detections = list(
        db.scalars(select(Detection).order_by(Detection.id.desc()).limit(max(1, min(limit, 200)))).all()
    )
    return [_event_bundle(db, detection) for detection in detections]


def _latest_analysis(db: Session, detection_id: int) -> AttackAnalysis | None:
    statement = (
        select(AttackAnalysis)
        .where(AttackAnalysis.detection_id == detection_id)
        .order_by(AttackAnalysis.id.desc())
        .limit(1)
    )
    return db.scalars(statement).first()


def _latest_risk(db: Session, detection_id: int) -> RiskAssessment | None:
    statement = (
        select(RiskAssessment)
        .where(RiskAssessment.detection_id == detection_id)
        .order_by(RiskAssessment.id.desc())
        .limit(1)
    )
    return db.scalars(statement).first()


def _event_bundle(db: Session, detection: Detection) -> dict[str, Any]:
    log = db.get(AttackLog, detection.attack_log_id) if detection.attack_log_id else None
    analysis = _latest_analysis(db, detection.id)
    risk = _latest_risk(db, detection.id)
    return _serialize_event_row(detection, log, analysis, risk)


def list_alerts(db: Session, *, levels: list[str] | None = None, limit: int = 50) -> list[dict[str, Any]]:
    wanted = {item.upper() for item in (levels or list(ALERT_LEVELS))}
    latest_risk = _latest_risk_ids()
    statement = (
        select(RiskAssessment)
        .join(latest_risk, RiskAssessment.id == latest_risk.c.id)
        .where(RiskAssessment.risk_level.in_(tuple(wanted)))
        .order_by(RiskAssessment.risk_score.desc(), RiskAssessment.id.desc())
        .limit(max(1, min(limit, 200)))
    )
    rows = list(db.scalars(statement).all())
    results = []
    for risk in rows:
        if risk.detection_id is None:
            continue
        detection = db.get(Detection, risk.detection_id)
        if detection is None:
            continue
        results.append(_event_bundle(db, detection))
    return results


def list_activity_logs(
    db: Session,
    *,
    source_ip: str | None = None,
    risk_level: str | None = None,
    classification: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    statement = select(AttackLog)
    count_statement = select(func.count()).select_from(AttackLog)
    if source_ip:
        needle = source_ip.strip()
        statement = statement.where(AttackLog.ip_address.contains(needle))
        count_statement = count_statement.where(AttackLog.ip_address.contains(needle))
    if risk_level:
        level = risk_level.strip().upper()
        statement = statement.where(AttackLog.risk_level == level)
        count_statement = count_statement.where(AttackLog.risk_level == level)
    class_filter = classification.strip().lower() if classification else None
    if class_filter:
        latest_det = (
            select(Detection.attack_log_id, func.max(Detection.id).label("id"))
            .where(Detection.attack_log_id.is_not(None))
            .group_by(Detection.attack_log_id)
            .subquery()
        )
        statement = (
            statement.join(latest_det, latest_det.c.attack_log_id == AttackLog.id)
            .join(Detection, Detection.id == latest_det.c.id)
            .where(Detection.classification == class_filter)
        )
        count_statement = (
            select(func.count())
            .select_from(AttackLog)
            .join(latest_det, latest_det.c.attack_log_id == AttackLog.id)
            .join(Detection, Detection.id == latest_det.c.id)
            .where(Detection.classification == class_filter)
        )
        if source_ip:
            count_statement = count_statement.where(AttackLog.ip_address.contains(source_ip.strip()))
        if risk_level:
            count_statement = count_statement.where(AttackLog.risk_level == risk_level.strip().upper())

    logs = list(
        db.scalars(
            statement.order_by(AttackLog.timestamp.desc(), AttackLog.id.desc())
            .offset(max(0, offset))
            .limit(max(1, min(limit, 200)))
        ).all()
    )
    items = []
    for log in logs:
        latest_detection = db.scalars(
            select(Detection).where(Detection.attack_log_id == log.id).order_by(Detection.id.desc()).limit(1)
        ).first()
        if latest_detection is not None:
            items.append(_event_bundle(db, latest_detection))
        else:
            items.append(
                {
                    "detection_id": None,
                    "attack_log_id": log.id,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "source_ip": log.ip_address,
                    "status": log.status,
                    "classification": None,
                    "confidence_score": None,
                    "attack_category": None,
                    "indicators": [],
                    "evidence_strength": None,
                    "risk_score": None,
                    "risk_level": log.risk_level,
                    "recommended_action": None,
                    "operator_guidance": None,
                    "is_demo": (log.status or "").lower() == "demo",
                }
            )
    total = int(db.scalar(count_statement) or 0)
    return {"count": total, "items": items, "limit": limit, "offset": offset}


def event_detail(db: Session, detection_id: int) -> dict[str, Any]:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise LookupError(f"Detection {detection_id} was not found.")
    log = db.get(AttackLog, detection.attack_log_id) if detection.attack_log_id else None
    analysis = _latest_analysis(db, detection.id)
    risk = _latest_risk(db, detection.id)
    summary = _serialize_event_row(detection, log, analysis, risk)
    explanation = detection.explanation if isinstance(detection.explanation, dict) else None
    return {
        **summary,
        "attempts": log.attempts if log is not None else None,
        "commands": list(log.commands or []) if log is not None else [],
        "analysis": None
        if analysis is None
        else {
            "attack_category": analysis.attack_category,
            "indicators": list(analysis.indicators or []),
            "secondary_categories": list(analysis.secondary_categories or []),
            "evidence": analysis.evidence or {},
            "evidence_strength": analysis.evidence_strength,
            "features": analysis.features or {},
            "insufficient_evidence_reason": analysis.insufficient_evidence_reason,
        },
        "risk": None
        if risk is None
        else {
            "risk_score": risk.risk_score,
            "risk_level": risk.risk_level,
            "recommended_action": risk.recommended_action,
            "operator_guidance": risk.operator_guidance,
            "execution_status": risk.execution_status,
            "decision_reason": list(risk.decision_reason or []),
            "risk_breakdown": risk.risk_breakdown or {},
            "action_is_recommendation": True,
        },
        "explanation": explanation,
    }


def system_status(db: Session) -> dict[str, Any]:
    try:
        db.scalar(select(func.count()).select_from(AttackLog))
        database = {"status": "ok", "engine": "sqlite" if DATABASE_URL.startswith("sqlite") else "configured"}
    except Exception:
        database = {"status": "error", "engine": "unknown"}
    artifact = model_path()
    registry = load_registry() if artifact.is_file() else None
    events_ingested = int(db.scalar(select(func.count()).select_from(HoneypotEvent)) or 0)
    return {
        "backend": {"status": "ok"},
        "database": database,
        "ml_model": {
            "loaded": artifact.is_file(),
            "model_name": registry.model_name if registry else None,
            "model_version": registry.model_version if registry else None,
            "dataset_kind": registry.dataset_kind if registry else None,
        },
        "collector": {
            "mode": "simulated_jsonl",
            "events_ingested": events_ingested,
            "sample_log_present": SAMPLE_LOG.is_file(),
        },
        "realtime": {
            "websocket_path": "/ws/events",
            "connected_clients": get_connection_manager().connection_count(),
            "authentication": "not_implemented",
        },
        "notes": [
            "BLOCK/CONTAIN is a recommendation only.",
            "Collector status describes simulated JSONL ingestion, not a public honeypot.",
            "Dashboard WebSocket clients are not authenticated; use only in the controlled project environment.",
        ],
    }
