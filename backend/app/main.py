import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.database import Base, engine
from app.models import AttackLog, Detection, HoneypotEvent  # noqa: F401  (register model metadata)
from app.routes.collector import router as collector_router
from app.routes.detection import router as detection_router
from app.routes.features import router as features_router
from app.routes.logs import router as logs_router

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


def _cors_origins() -> list[str]:
    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Intelligent IDS API",
    description="Backend API for the Honeypot-Assisted Interpretable AI IDS.",
    version="0.4.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs_router)
app.include_router(collector_router)
app.include_router(features_router)
app.include_router(detection_router)


@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(_, __):
    return JSONResponse(
        status_code=500,
        content={"detail": "A database error occurred."},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
