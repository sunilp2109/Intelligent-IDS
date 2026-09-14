def test_create_list_get_delete_log(client):
    created = client.post(
        "/api/logs",
        json={
            "ip_address": "203.0.113.8",
            "attempts": 2,
            "commands": ["whoami"],
            "status": "collected",
            "risk_level": "unscored",
        },
    )
    assert created.status_code == 201
    log_id = created.json()["id"]
    listed = client.get("/api/logs")
    assert listed.status_code == 200
    assert any(item["id"] == log_id for item in listed.json())
    fetched = client.get(f"/api/logs/{log_id}")
    assert fetched.status_code == 200
    assert fetched.json()["ip_address"] == "203.0.113.8"
    deleted = client.delete(f"/api/logs/{log_id}")
    assert deleted.status_code == 204
    missing = client.get(f"/api/logs/{log_id}")
    assert missing.status_code == 404


def test_create_log_rejects_invalid_ip(client):
    response = client.post(
        "/api/logs",
        json={
            "ip_address": "not-an-ip",
            "attempts": 1,
            "commands": [],
            "status": "collected",
            "risk_level": "unscored",
        },
    )
    assert response.status_code == 422


def test_create_log_rejects_negative_attempts(client):
    response = client.post(
        "/api/logs",
        json={
            "ip_address": "203.0.113.8",
            "attempts": -1,
            "commands": [],
            "status": "collected",
            "risk_level": "unscored",
        },
    )
    assert response.status_code == 422
