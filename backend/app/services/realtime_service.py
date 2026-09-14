from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal

from app.services.websocket_manager import get_connection_manager

logger = logging.getLogger("intelligent_ids.realtime")

EventType = Literal[
    "security_event",
    "detection_created",
    "risk_assessed",
    "alert_created",
    "system_status",
]

EVENT_TYPES: frozenset[str] = frozenset(
    {"security_event", "detection_created", "risk_assessed", "alert_created", "system_status"}
)
ALERT_LEVELS = frozenset({"HIGH", "CRITICAL"})
PAYLOAD_DATA_FIELDS = (
    "log_id",
    "detection_id",
    "source_ip",
    "classification",
    "confidence_score",
    "attack_category",
    "risk_score",
    "risk_level",
    "recommended_action",
    "xai_status",
    "pipeline_status",
    "reason",
    "status",
    "clients",
    "heartbeat_seconds",
)
SENSITIVE_KEYS = frozenset(
    {
        "username",
        "password",
        "secret",
        "token",
        "command",
        "commands",
        "explanation",
        "features",
        "shap_values",
        "top_features",
        "path",
        "file",
        "credential",
        "auth",
    }
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_event(event_type: EventType, data: dict[str, Any], *, timestamp: str | None = None) -> dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unsupported event type: {event_type}")
    compact = {key: data[key] for key in PAYLOAD_DATA_FIELDS if key in data and data[key] is not None}
    leaked = SENSITIVE_KEYS.intersection(compact)
    if leaked:
        raise ValueError(f"Refusing to broadcast sensitive field(s): {', '.join(sorted(leaked))}")
    return {
        "event_type": event_type,
        "timestamp": timestamp or utc_now_iso(),
        "data": compact,
    }


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key).lower()
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def payload_contains_sensitive_data(payload: dict[str, Any]) -> bool:
    return any(key in SENSITIVE_KEYS for key in _walk_keys(payload))


def build_security_event_payload(
    *,
    log_id: int,
    source_ip: str,
    classification: str,
    confidence_score: float,
    attack_category: str,
    risk_score: int,
    risk_level: str,
    recommended_action: str,
    detection_id: int | None = None,
    xai_status: str = "unavailable",
    timestamp: str | None = None,
) -> dict[str, Any]:
    return build_event(
        "security_event",
        {
            "log_id": log_id,
            "detection_id": detection_id,
            "source_ip": source_ip,
            "classification": classification,
            "confidence_score": confidence_score,
            "attack_category": attack_category,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": recommended_action,
            "xai_status": xai_status,
            "pipeline_status": "complete",
        },
        timestamp=timestamp,
    )


def build_system_status_payload(
    status: str,
    *,
    reason: str | None = None,
    log_id: int | None = None,
    source_ip: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "status": status,
        "clients": get_connection_manager().connection_count(),
    }
    if reason:
        data["reason"] = reason
    if log_id is not None:
        data["log_id"] = log_id
    if source_ip:
        data["source_ip"] = source_ip
    if extra:
        data.update(extra)
    return build_event("system_status", data)


def broadcast_event(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict) or payload.get("event_type") not in EVENT_TYPES:
        logger.warning("Skipping malformed realtime payload")
        return
    get_connection_manager().broadcast_threadsafe(payload)


def broadcast_security_event(payload: dict[str, Any]) -> None:
    broadcast_event(payload)
    data = payload.get("data") or {}
    if str(data.get("risk_level") or "").upper() in ALERT_LEVELS:
        broadcast_event(build_event("alert_created", dict(data), timestamp=payload.get("timestamp")))


def broadcast_detection_created(data: dict[str, Any], *, timestamp: str | None = None) -> None:
    broadcast_event(build_event("detection_created", data, timestamp=timestamp))


def broadcast_risk_assessed(data: dict[str, Any], *, timestamp: str | None = None) -> None:
    broadcast_event(build_event("risk_assessed", data, timestamp=timestamp))


def broadcast_system_status(
    status: str,
    *,
    reason: str | None = None,
    log_id: int | None = None,
    source_ip: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    broadcast_event(
        build_system_status_payload(
            status,
            reason=reason,
            log_id=log_id,
            source_ip=source_ip,
            extra=extra,
        )
    )


async def send_to_client(websocket: Any, payload: dict[str, Any]) -> bool:
    return await get_connection_manager().send_to_client(websocket, payload)
