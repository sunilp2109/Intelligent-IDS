from ml.models.train import train_and_save
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.scripts.build_development_dataset import build_development_rows
import pandas as pd


def _payload(**overrides):
    body = {name: 0 for name in FEATURE_NAMES}
    body.update(
        {
            "total_events": 4,
            "login_attempts": 4,
            "failed_login_attempts": 3,
            "successful_login_attempts": 1,
            "failed_login_ratio": 0.75,
            "attempts_per_minute": 2.5,
            "session_duration_seconds": 90,
            "events_per_minute": 2.5,
            "unique_source_ip_count": 1,
        }
    )
    body.update(overrides)
    return body


def test_predict_without_trained_model_returns_503(client, monkeypatch, tmp_path):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    response = client.post("/api/detection/predict", json=_payload())
    assert response.status_code == 503
    assert "Train one first" in response.json()["detail"]


def test_predict_rejects_missing_feature(client):
    payload = _payload()
    payload.pop("failed_login_attempts")
    response = client.post("/api/detection/predict", json=payload)
    assert response.status_code == 422


def test_predict_with_trained_model_returns_probability(client, monkeypatch, tmp_path):
    dataset = tmp_path / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path))
    response = client.post("/api/detection/predict", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] in {"normal", "suspicious", "malicious"}
    assert 0.0 <= body["confidence_score"] <= 1.0
    assert body["explanation"] is None
    assert abs(sum(body["class_probabilities"].values()) - 1.0) < 1e-6
