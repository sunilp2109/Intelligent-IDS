import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / ".env")


def _build_database_url() -> str:
    """Return the SQLAlchemy URL.

    SQLite is the Module 1 default. A PostgreSQL URL from DATABASE_URL
    is used as-is so later modules can switch engines without rewriting
    application code.
    """
    configured = os.getenv("DATABASE_URL", "sqlite:///./ids.db").strip()
    if configured.startswith("sqlite:///./"):
        relative_path = configured.removeprefix("sqlite:///./")
        sqlite_path = (BACKEND_DIR / relative_path).resolve()
        return f"sqlite:///{sqlite_path.as_posix()}"
    return configured


DATABASE_URL = _build_database_url()

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


@event.listens_for(engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
