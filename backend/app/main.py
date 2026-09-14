import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.database import Base, engine
from app.models import AttackLog  # noqa: F401  (register model metadata)
from app.routes.logs import router as logs_router

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


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
    description="Backend API foundation for the Honeypot-Assisted Interpretable AI IDS.",
    version="0.1.0",
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


@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(_, __):
    return JSONResponse(
        status_code=500,
        content={"detail": "A database error occurred."},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
