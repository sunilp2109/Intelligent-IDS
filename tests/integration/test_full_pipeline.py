from pathlib import Path

import pandas as pd
from sqlalchemy import select

from app.models import AttackAnalysis, Detection, HoneypotEvent, RiskAssessment
from app.services.pipeline import process_security_event
from app.services.websocket_manager import get_connection_manager
from ml.models.train import train_and_save
from ml.scripts.build_development_dataset import build_development_rows
from tests.support import load_fixture


def test_full_pipeline_persists_every_stage_and_broadcasts(client, db_session, monkeypatch, tmp_path):
    dataset = tmp_path / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path))

    events, failures = load_fixture("brute_force.jsonl")
    assert failures == []
    with client.websocket_connect("/ws/events") as ws:
        assert ws.receive_json()["event_type"] == "system_status"
        last = None
        for event in events:
            last = process_security_event(db_session, event)
        assert last is not None
        assert last.status == "complete"
        assert last.detection_id is not None
        assert last.analysis_id is not None
        assert last.risk_id is not None
        assert last.xai_status in {"stored", "unavailable"}

        payload = None
        for _ in range(80):
            message = ws.receive_json()
            if message.get("event_type") != "security_event":
                continue
            payload = message
            if message.get("data", {}).get("detection_id") == last.detection_id:
                break
        assert payload is not None
        data = payload["data"]
        assert data["log_id"] == last.ingest.attack_log_id
        assert data["detection_id"] == last.detection_id
        assert data["classification"] in {"normal", "suspicious", "malicious"}
        assert data["attack_category"]
        assert data["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert "username" not in data
        assert "command" not in data
        assert "password" not in data

    assert db_session.scalar(select(HoneypotEvent).where(HoneypotEvent.source_ip == "203.0.113.20")) is not None
    detection = db_session.get(Detection, last.detection_id)
    assert detection is not None
    assert db_session.get(AttackAnalysis, last.analysis_id) is not None
    assert db_session.get(RiskAssessment, last.risk_id) is not None
    if last.xai_status == "stored":
        assert isinstance(detection.explanation, dict)
        assert detection.explanation.get("top_features")
    assert get_connection_manager().connection_count() == 0
    assert Path(tmp_path / "intrusion_model.joblib").is_file()
