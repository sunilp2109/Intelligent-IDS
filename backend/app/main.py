import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.config import cors_origins, websocket_heartbeat_seconds
from app.database import Base, engine
from app.models import AttackAnalysis, AttackLog, Detection, HoneypotEvent, RiskAssessment  # noqa: F401
from app.routes.analysis import router as analysis_router
from app.routes.collector import router as collector_router
from app.routes.dashboard import router as dashboard_router
from app.routes.detection import router as detection_router
from app.routes.explain import router as explain_router
from app.routes.features import router as features_router
from app.routes.logs import router as logs_router
from app.routes.risk import router as risk_router
from app.routes.websocket import router as websocket_router
from app.services.realtime_service import broadcast_system_status
from app.services.websocket_manager import get_connection_manager

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


async def _heartbeat_loop() -> None:
    interval = websocket_heartbeat_seconds()
    if interval <= 0:
        return
    manager = get_connection_manager()
    try:
        while True:
            await asyncio.sleep(interval)
            if manager.connection_count() == 0:
                continue
            broadcast_system_status("ok", extra={"heartbeat_seconds": interval})
    except asyncio.CancelledError:
        return


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    manager = get_connection_manager()
    manager.bind_loop(asyncio.get_running_loop())
    heartbeat = asyncio.create_task(_heartbeat_loop())
    try:
        yield
    finally:
        heartbeat.cancel()
        await manager.disconnect_all()


app = FastAPI(
    title="Intelligent IDS API",
    description="Backend API for the Honeypot-Assisted Interpretable AI IDS.",
    version="0.10.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs_router)
app.include_router(collector_router)
app.include_router(features_router)
app.include_router(detection_router)
app.include_router(analysis_router)
app.include_router(explain_router)
app.include_router(risk_router)
app.include_router(dashboard_router)
app.include_router(websocket_router)


@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(_, __):
    return JSONResponse(
        status_code=500,
        content={"detail": "A database error occurred."},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
