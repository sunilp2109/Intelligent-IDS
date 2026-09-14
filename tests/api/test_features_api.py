from datetime import datetime, timedelta, timezone


def _login(offset_seconds: int, *, success: bool) -> dict:
    started = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "timestamp": (started + timedelta(seconds=offset_seconds)).isoformat(),
        "source_ip": "192.168.1.80",
        "event_type": "login_attempt",
        "username": "admin",
        "success": success,
        "command": None,
    }


def test_features_api_empty_database(client):
    response = client.get("/api/features")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 0
    assert body["feature_vectors"] == []


def test_features_api_calculates_from_inserted_events(client):
    for index in range(8):
        response = client.post("/api/collector/events", json=_login(index, success=False))
        assert response.status_code == 200
        assert response.json()["result"] == "inserted"
    for index in range(8, 10):
        response = client.post("/api/collector/events", json=_login(index, success=True))
        assert response.status_code == 200

    response = client.get("/api/features")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    features = body["feature_vectors"][0]["features"]
    assert features["login_attempts"] == 10
    assert features["failed_login_attempts"] == 8
    assert features["successful_login_attempts"] == 2
    assert features["failed_login_ratio"] == 0.8
    assert body["feature_vectors"][0]["source_ip"] == "192.168.1.80"
    assert len(body["feature_vectors"][0]["feature_vector"]) == 15

    filtered = client.get("/api/features", params={"source_ip": "192.168.1.80"})
    assert filtered.json()["count"] == 1
    missing = client.get("/api/features", params={"source_ip": "10.0.0.1"})
    assert missing.json()["count"] == 0


def test_features_export_csv(client, tmp_path):
    client.post("/api/collector/events", json=_login(0, success=False))
    response = client.post("/api/features/export")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["file"].endswith("features.csv")
