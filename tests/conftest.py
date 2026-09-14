import os
from pathlib import Path

TEST_DB = Path(__file__).resolve().parent / "_test_ids.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.resolve().as_posix()}"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import AttackLog, HoneypotEvent  # noqa: F401


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
