from ml.explainability.shap_explainer import MISSING_MODEL_MESSAGE, clear_explainer_cache
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


def _train_model(tmp_path, monkeypatch):
    dataset = tmp_path / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path))
    clear_explainer_cache()


def test_explain_without_trained_model_returns_503(client, monkeypatch, tmp_path):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    response = client.post("/api/explain", json=_payload())
    assert response.status_code == 503
    assert response.json()["detail"] == MISSING_MODEL_MESSAGE


def test_explain_rejects_missing_feature(client):
    payload = _payload()
    payload.pop("failed_login_attempts")
    response = client.post("/api/explain", json=payload)
    assert response.status_code == 422


def test_explain_rejects_invalid_feature_value(client):
    payload = _payload(login_attempts="nope")
    response = client.post("/api/explain", json=payload)
    assert response.status_code == 422


def test_explain_response_structure(client, monkeypatch, tmp_path):
    _train_model(tmp_path, monkeypatch)
    response = client.post("/api/explain", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] in {"normal", "suspicious", "malicious"}
    assert 0.0 <= body["confidence_score"] <= 1.0
    explanation = body["explanation"]
    assert explanation["explained_class"] == body["classification"]
    assert isinstance(explanation["base_value"], float)
    assert len(explanation["feature_contributions"]) == len(FEATURE_NAMES)
    assert len(explanation["top_features"]) == 5
    assert explanation["top_features"][0]["feature"] in FEATURE_NAMES
    for item in explanation["feature_contributions"]:
        assert item["feature"] in FEATURE_NAMES
        assert isinstance(item["shap_value"], float)
        assert item["direction"] in {
            "increases_prediction",
            "decreases_prediction",
            "no_effect",
        }
    assert explanation["explainer_type"] == "TreeExplainer"
    assert "visual_data" in explanation
    assert "contributed to the model's prediction" in explanation["summary_text"]


def test_explain_stores_json_on_existing_detection(client, monkeypatch, tmp_path):
    _train_model(tmp_path, monkeypatch)
    created = client.post(
        "/api/logs",
        json={
            "ip_address": "192.168.1.50",
            "attempts": 4,
            "commands": [],
            "status": "collected",
            "risk_level": "unscored",
        },
    )
    assert created.status_code == 201
    log_id = created.json()["id"]
    predicted = client.post("/api/detection/predict", json=_payload(log_id=log_id))
    assert predicted.status_code == 200
    detection_id = predicted.json()["detection_id"]
    assert predicted.json()["explanation"] is None

    explained = client.post("/api/explain", json=_payload(detection_id=detection_id))
    assert explained.status_code == 200
    assert explained.json()["detection_id"] == detection_id

    stored = client.get(f"/api/detection/{detection_id}")
    assert stored.status_code == 200
    explanation = stored.json()["explanation"]
    assert isinstance(explanation, dict)
    assert explanation["explained_class"] in {"normal", "suspicious", "malicious"}
    assert explanation["top_features"]

    recount = client.post("/api/explain", json=_payload(detection_id=detection_id))
    assert recount.status_code == 200
    assert recount.json()["detection_id"] == detection_id
    missing = client.post("/api/explain", json=_payload(detection_id=99999))
    assert missing.status_code == 404
