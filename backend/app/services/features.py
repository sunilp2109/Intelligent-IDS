from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AttackLog, HoneypotEvent
from ml.preprocessing.feature_extractor import extract_features, extract_session_features
from ml.preprocessing.feature_schema import to_feature_vector

logger = logging.getLogger("intelligent_ids.features")


def _event_payload(event: HoneypotEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source_ip": event.source_ip,
        "event_type": event.event_type,
        "username": event.username,
        "success": event.success,
        "command": event.command,
    }


def _session_record(
    features: dict[str, Any],
    *,
    source_ip: str | None,
    source_ips: list[str],
    session_start: str | None,
    session_end: str | None,
    attack_log_id: int | None = None,
) -> dict[str, Any]:
    return {
        "attack_log_id": attack_log_id,
        "source_ip": source_ip,
        "source_ips": source_ips,
        "session_start": session_start,
        "session_end": session_end,
        "features": features,
        "feature_vector": to_feature_vector(features),
    }


def extract_features_from_db(
    db: Session,
    *,
    source_ip: str | None = None,
    log_id: int | None = None,
    window_minutes: int | None = None,
) -> list[dict[str, Any]]:
    """Load stored honeypot events and return calculated behavioral feature vectors.

    Default grouping reuses Module 2 AttackLog sessions (source IP + time window).
    Pass window_minutes to re-sessionize from raw events instead.
    """
    statement = select(HoneypotEvent).order_by(HoneypotEvent.timestamp.asc())
    if log_id is not None:
        statement = statement.where(HoneypotEvent.attack_log_id == log_id)
    if source_ip:
        statement = statement.where(HoneypotEvent.source_ip == source_ip)

    events = list(db.scalars(statement).all())
    logger.info(
        "Feature extraction loaded events=%s source_ip=%s log_id=%s",
        len(events),
        source_ip or "*",
        log_id or "*",
    )
    if not events:
        return []

    if window_minutes is not None:
        records = extract_session_features(
            [_event_payload(event) for event in events],
            window_minutes=window_minutes,
        )
        logger.info("Feature extraction produced sessions=%s grouping=window", len(records))
        return records

    grouped: dict[int | None, list[HoneypotEvent]] = {}
    for event in events:
        grouped.setdefault(event.attack_log_id, []).append(event)

    records: list[dict[str, Any]] = []
    for attack_log_id, session_events in grouped.items():
        features = extract_features([_event_payload(event) for event in session_events])
        if not features:
            continue
        source_ips = sorted({event.source_ip for event in session_events})
        timestamps = [event.timestamp for event in session_events]
        source_ip_value = source_ips[0] if len(source_ips) == 1 else None
        if source_ip_value is None and attack_log_id is not None:
            attack_log = db.get(AttackLog, attack_log_id)
            source_ip_value = attack_log.ip_address if attack_log else None
        records.append(
            _session_record(
                features,
                source_ip=source_ip_value,
                source_ips=source_ips,
                session_start=min(timestamps).isoformat() if timestamps else None,
                session_end=max(timestamps).isoformat() if timestamps else None,
                attack_log_id=attack_log_id,
            )
        )

    records.sort(key=lambda item: (item.get("session_start") or "", item.get("source_ip") or ""))
    logger.info("Feature extraction produced sessions=%s grouping=attack_log", len(records))
    return records
