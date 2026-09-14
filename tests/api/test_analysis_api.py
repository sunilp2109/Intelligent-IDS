from ml.preprocessing.feature_schema import FEATURE_NAMES


def _analyze_payload(**overrides):
    body = {name: 0 for name in FEATURE_NAMES}
    body.update(
        {
            "total_events": 2,
            "login_attempts": 1,
            "successful_login_attempts": 1,
            "classification": "normal",
            "confidence_score": 0.9,
        }
    )
    body.update(overrides)
    return body


def test_analysis_api_accepts_valid_payload(client):
    response = client.post("/api/analysis/analyze", json=_analyze_payload())
    assert response.status_code == 200
    assert response.json()["attack_category"] == "NORMAL_ACTIVITY"


def test_analysis_api_rejects_invalid_confidence(client):
    response = client.post("/api/analysis/analyze", json=_analyze_payload(confidence_score=1.5))
    assert response.status_code == 422
