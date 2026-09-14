from __future__ import annotations

import os


def cors_origins() -> list[str]:
    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://localhost:5174,http://127.0.0.1:3000,http://127.0.0.1:5173,http://127.0.0.1:5174",
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def websocket_heartbeat_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("WS_HEARTBEAT_SECONDS", "30")))
    except ValueError:
        return 30.0


def websocket_send_timeout_seconds() -> float:
    try:
        return max(0.5, float(os.getenv("WS_SEND_TIMEOUT_SECONDS", "2")))
    except ValueError:
        return 2.0


def websocket_origin_allowed(origin: str | None) -> bool:
    """Allow configured dashboard origins. Missing Origin is for tests/non-browser clients."""
    if not origin:
        return True
    allowed = set(cors_origins())
    allowed.update({"http://testserver", "https://testserver"})
    return origin in allowed
