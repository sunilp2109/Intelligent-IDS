from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import websocket_heartbeat_seconds
from app.services.realtime_service import build_system_status_payload, send_to_client
from app.services.websocket_manager import get_connection_manager

logger = logging.getLogger("intelligent_ids.websocket")

router = APIRouter(tags=["realtime"])


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    manager = get_connection_manager()
    accepted = await manager.connect(websocket)
    if not accepted:
        return
    await send_to_client(
        websocket,
        build_system_status_payload(
            "connected",
            extra={"heartbeat_seconds": websocket_heartbeat_seconds()},
        ),
    )
    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            try:
                message = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                logger.warning("Ignoring malformed WebSocket message")
                continue
            if not isinstance(message, dict):
                continue
            if message.get("type") == "ping" or message.get("event_type") == "ping":
                await send_to_client(websocket, build_system_status_payload("ok"))
    finally:
        await manager.disconnect(websocket)
