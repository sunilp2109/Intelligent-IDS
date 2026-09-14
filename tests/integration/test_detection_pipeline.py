import pandas as pd
import pytest

from app.services.features import extract_features_from_db
from app.services.ingestion import ingest_event
from honeypot.parser.log_parser import normalize_event_payload
from ml.analysis.analyzer import analyze_activity
from ml.explainability.shap_explainer import explain_features
from ml.models.predict import predict_features
from ml.models.train import train_and_save
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.risk.engine import assess_risk
from ml.scripts.build_development_dataset import build_development_rows
from tests.support import load_fixture


def _train(tmp_path, monkeypatch):
    dataset = tmp_path / "dev.csv"
    pd.DataFrame(build_development_rows(per_class=8)).to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path))
    return tmp_path


def test_collection_feeds_feature_extraction(db_session):
    events, failures = load_fixture("brute_force.jsonl")
    assert failures == []
    for event in events:
        ingest_event(db_session, event)
    records = extract_features_from_db(db_session, source_ip="203.0.113.20")
    assert len(records) == 1
    features = records[0]["features"]
    assert features["login_attempts"] == 12
    assert features["failed_login_attempts"] == 11
    assert 0.8 <= features["failed_login_ratio"] <= 1.0


def test_features_feed_ml_detection(tmp_path, monkeypatch):
    _train(tmp_path, monkeypatch)
    events, _failures = load_fixture("normal_activity.jsonl")
    from ml.preprocessing.feature_extractor import extract_features

    features = extract_features([event.to_dict() for event in events])
    prediction = predict_features(features, directory=tmp_path)
    assert prediction["classification"] in {"normal", "suspicious", "malicious"}
    assert 0.0 <= prediction["confidence_score"] <= 1.0
    assert abs(sum(prediction["class_probabilities"].values()) - 1.0) < 1e-6


def test_ml_output_feeds_attack_analysis():
    events, _failures = load_fixture("brute_force.jsonl")
    from ml.preprocessing.feature_extractor import extract_features

    features = extract_features([event.to_dict() for event in events])
    analysis = analyze_activity(
        features,
        {"classification": "malicious", "confidence_score": 0.94},
    )
    assert analysis["attack_category"] == "BRUTE_FORCE"
    assert analysis["classification"] == "malicious"
    assert "HIGH_FAILED_LOGIN_RATIO" in analysis["indicators"]


def test_ml_output_feeds_shap(tmp_path, monkeypatch):
    _train(tmp_path, monkeypatch)
    features = {name: 0.0 for name in FEATURE_NAMES}
    features.update(
        {
            "total_events": 12,
            "login_attempts": 12,
            "failed_login_attempts": 11,
            "failed_login_ratio": 0.916,
            "session_duration_seconds": 22,
            "attempts_per_minute": 32.7,
            "events_per_minute": 32.7,
            "unique_username_count": 3,
            "unique_source_ip_count": 1,
        }
    )
    explained = explain_features(features, directory=tmp_path)
    assert explained["classification"] in {"normal", "suspicious", "malicious"}
    top = explained["explanation"]["top_features"]
    assert top
    assert {item["feature"] for item in top}.issubset(set(FEATURE_NAMES))


def test_analysis_and_ml_feed_risk():
    events, _failures = load_fixture("brute_force.jsonl")
    from ml.preprocessing.feature_extractor import extract_features

    features = extract_features([event.to_dict() for event in events])
    analysis = analyze_activity(features, {"classification": "malicious", "confidence_score": 0.94})
    risk = assess_risk(
        classification="malicious",
        confidence_score=0.94,
        attack_category=analysis["attack_category"],
        evidence_strength=analysis["evidence_strength"],
        features=features,
        indicators=analysis["indicators"],
    )
    assert 0 <= risk["risk_score"] <= 100
    assert risk["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert risk["recommended_action"] in {"ALLOW", "ALERT", "BLOCK"}
    assert risk["execution_status"] == "recommendation_only"


def test_missing_model_does_not_invent_a_class(tmp_path, monkeypatch):
    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing"))
    from ml.models.predict import ModelNotFoundError

    with pytest.raises(ModelNotFoundError):
        predict_features({name: 0 for name in FEATURE_NAMES}, directory=tmp_path / "missing")
