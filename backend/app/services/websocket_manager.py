from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.config import websocket_origin_allowed, websocket_send_timeout_seconds

logger = logging.getLogger("intelligent_ids.websocket")


class ConnectionManager:
    """Tracks dashboard WebSocket clients. Broadcast failures must not crash the API."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def connection_count(self) -> int:
        return len(self._connections)

    def connections(self) -> list[WebSocket]:
        return list(self._connections)

    async def connect(self, websocket: WebSocket) -> bool:
        origin = websocket.headers.get("origin")
        if not websocket_origin_allowed(origin):
            logger.warning("Rejected WebSocket origin=%s", origin)
            await websocket.close(code=1008)
            return False
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        logger.info("WebSocket connected clients=%s", len(self._connections))
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close()
            except Exception:
                logger.debug("WebSocket already closed during disconnect")
        logger.info("WebSocket disconnected clients=%s", len(self._connections))

    async def disconnect_all(self) -> None:
        async with self._lock:
            clients = list(self._connections)
            self._connections.clear()
        for websocket in clients:
            if websocket.client_state != WebSocketState.CONNECTED:
                continue
            try:
                await websocket.close()
            except Exception:
                logger.debug("Failed to close WebSocket during shutdown")

    async def send_to_client(self, websocket: WebSocket, message: dict[str, Any]) -> bool:
        try:
            await asyncio.wait_for(
                websocket.send_json(message),
                timeout=websocket_send_timeout_seconds(),
            )
            return True
        except (WebSocketDisconnect, asyncio.TimeoutError, Exception) as exc:
            logger.warning("WebSocket send failed: %s", type(exc).__name__)
            await self._drop(websocket)
            return False

    async def broadcast(self, message: dict[str, Any]) -> None:
        async with self._lock:
            clients = list(self._connections)
        if not clients:
            return
        results = await asyncio.gather(
            *[self._safe_send(websocket, message) for websocket in clients],
            return_exceptions=True,
        )
        for websocket, result in zip(clients, results, strict=True):
            if result is True:
                continue
            await self._drop(websocket)

    def broadcast_threadsafe(self, message: dict[str, Any]) -> None:
        """Schedule a broadcast from sync pipeline/ingest code without blocking other clients."""
        if not self._connections:
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None and running.is_running():
            running.create_task(self.broadcast(message))
            return
        loop = self._loop
        if loop is None or not loop.is_running():
            logger.warning("No running event loop; WebSocket broadcast skipped")
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)

    async def _safe_send(self, websocket: WebSocket, message: dict[str, Any]) -> bool:
        try:
            await asyncio.wait_for(
                websocket.send_json(message),
                timeout=websocket_send_timeout_seconds(),
            )
            return True
        except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
            return False

    async def _drop(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close()
            except Exception:
                logger.debug("Unhealthy WebSocket already closed")


_manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    return _manager


def reset_connection_manager() -> ConnectionManager:
    """Test helper: drop in-memory client tracking without touching the event loop."""
    _manager._connections.clear()
    return _manager
