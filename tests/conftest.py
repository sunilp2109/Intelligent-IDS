import os
from pathlib import Path

TEST_DB = Path(__file__).resolve().parent / "_test_ids.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.resolve().as_posix()}"
os.environ.setdefault("WS_HEARTBEAT_SECONDS", "0")
# Do not reuse a developer-trained artifact from ml/artifacts/.
os.environ["ML_ARTIFACT_DIR"] = str((Path(__file__).resolve().parent / "_no_model").resolve())

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import AttackLog, HoneypotEvent  # noqa: F401
from app.services.websocket_manager import reset_connection_manager


def pytest_collection_modifyitems(config, items):
    for item in items:
        path = Path(str(item.fspath)).as_posix()
        if "/unit/" in path:
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in path:
            item.add_marker(pytest.mark.integration)
        elif "/api/" in path:
            item.add_marker(pytest.mark.api)
        elif "/realtime/" in path:
            item.add_marker(pytest.mark.realtime)
        elif "/performance/" in path:
            item.add_marker(pytest.mark.performance)


@pytest.fixture
def client():
    reset_connection_manager()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    reset_connection_manager()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
