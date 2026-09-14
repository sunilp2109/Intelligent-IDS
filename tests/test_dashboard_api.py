from datetime import datetime, timezone

from app.models import AttackAnalysis, AttackLog, Detection, HoneypotEvent, RiskAssessment


def _log(db, *, ip, status="collected", risk="unscored", attempts=1, ts=None):
    record = AttackLog(
        timestamp=ts or datetime.now(timezone.utc),
        ip_address=ip,
        attempts=attempts,
        commands=[],
        status=status,
        risk_level=risk,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def _event(db, log, *, ip, event_type="login_attempt", ts=None):
    stamp = ts or datetime.now(timezone.utc)
    record = HoneypotEvent(
        event_hash=f"{ip}-{stamp.isoformat()}-{event_type}-{log.id}",
        timestamp=stamp,
        source_ip=ip,
        event_type=event_type,
        username="admin",
        success=False,
        command=None,
        attack_log_id=log.id,
    )
    db.add(record)
    db.commit()
    return record


def _detection(db, log, *, classification, confidence=0.9, explanation=None):
    record = Detection(
        attack_log_id=log.id,
        classification=classification,
        confidence_score=confidence,
        explanation=explanation,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def _analysis(db, detection, *, category, strength="MEDIUM", indicators=None):
    record = AttackAnalysis(
        detection_id=detection.id,
        attack_category=category,
        primary_indicator=(indicators or [category])[0],
        indicators=indicators or [],
        secondary_categories=[],
        evidence={"login_attempts": 4},
        evidence_strength=strength,
        features={"login_attempts": 4, "failed_login_ratio": 0.75},
        insufficient_evidence_reason=None,
    )
    db.add(record)
    db.commit()
    return record


def _risk(db, detection, *, score, level, action="ALERT"):
    record = RiskAssessment(
        detection_id=detection.id,
        risk_score=score,
        risk_level=level,
        recommended_action=action,
        operator_guidance="INVESTIGATE" if action == "ALERT" else "CONTAIN",
        execution_status="recommendation_only",
        decision_reason=["Stored dashboard test record"],
        risk_breakdown={"classification": 10, "confidence": 5, "attack_category": 8, "behavior": 4, "evidence_strength": 3, "override_adjustment": 0},
        overrides_applied=[],
        inputs_snapshot={"classification": detection.classification, "ml_confidence": detection.confidence_score},
    )
    db.add(record)
    db.commit()
    return record


def test_dashboard_stats_empty(client):
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    assert response.json() == {
        "total_events": 0,
        "normal": 0,
        "suspicious": 0,
        "malicious": 0,
        "critical": 0,
        "active_alerts": 0,
    }


def test_timeline_empty_database(client):
    response = client.get("/api/dashboard/timeline")
    assert response.status_code == 200
    assert response.json() == []


def test_attack_and_risk_distribution_empty(client):
    assert client.get("/api/dashboard/attacks").json() == []
    assert client.get("/api/dashboard/risks").json() == []
    assert client.get("/api/dashboard/recent").json() == []
    assert client.get("/api/dashboard/alerts").json() == []


def test_dashboard_aggregates_real_records(client, db_session):
    log_a = _log(db_session, ip="192.0.2.10", risk="LOW")
    log_b = _log(db_session, ip="192.0.2.11", risk="CRITICAL")
    _event(db_session, log_a, ip="192.0.2.10")
    _event(db_session, log_b, ip="192.0.2.11")
    det_a = _detection(db_session, log_a, classification="normal", confidence=0.91)
    det_b = _detection(db_session, log_b, classification="malicious", confidence=0.94)
    _analysis(db_session, det_a, category="NORMAL_ACTIVITY", strength="LOW")
    _analysis(db_session, det_b, category="BRUTE_FORCE", strength="HIGH", indicators=["HIGH_FAILED_LOGIN_RATIO"])
    _risk(db_session, det_a, score=8, level="LOW", action="ALLOW")
    _risk(db_session, det_b, score=91, level="CRITICAL", action="BLOCK")

    stats = client.get("/api/dashboard/stats").json()
    assert stats["total_events"] == 2
    assert stats["normal"] == 1
    assert stats["malicious"] == 1
    assert stats["suspicious"] == 0
    assert stats["critical"] == 1
    assert stats["active_alerts"] == 1

    attacks = client.get("/api/dashboard/attacks").json()
    assert attacks == [{"category": "BRUTE_FORCE", "count": 1}]

    risks = {row["level"]: row["count"] for row in client.get("/api/dashboard/risks").json()}
    assert risks["LOW"] == 1
    assert risks["CRITICAL"] == 1

    recent = client.get("/api/dashboard/recent").json()
    assert len(recent) == 2
    assert recent[0]["source_ip"] in {"192.0.2.10", "192.0.2.11"}
    assert recent[0]["classification"] in {"normal", "malicious"}

    alerts = client.get("/api/dashboard/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["risk_level"] == "CRITICAL"
    assert alerts[0]["recommended_action"] == "BLOCK"

    timeline = client.get("/api/dashboard/timeline").json()
    assert len(timeline) == 14
    assert sum(item["events"] for item in timeline) == 2
    assert sum(item["malicious"] for item in timeline) == 1
    assert sum(item["normal"] for item in timeline) == 1


def test_event_detail_includes_stored_pipeline(client, db_session):
    log = _log(db_session, ip="192.0.2.44", status="demo", risk="HIGH")
    explanation = {
        "explained_class": "malicious",
        "top_features": [
            {
                "feature": "failed_login_ratio",
                "value": 0.95,
                "shap_value": 0.12,
                "absolute_shap_value": 0.12,
                "direction": "increases_prediction",
            }
        ],
    }
    detection = _detection(db_session, log, classification="malicious", confidence=0.88, explanation=explanation)
    _analysis(db_session, detection, category="BRUTE_FORCE", strength="HIGH", indicators=["HIGH_LOGIN_ATTEMPTS"])
    _risk(db_session, detection, score=80, level="CRITICAL", action="BLOCK")

    response = client.get(f"/api/dashboard/events/{detection.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "malicious"
    assert body["attack_category"] == "BRUTE_FORCE"
    assert body["risk"]["risk_score"] == 80
    assert body["risk"]["action_is_recommendation"] is True
    assert body["explanation"]["top_features"][0]["feature"] == "failed_login_ratio"
    assert body["is_demo"] is True
    missing = client.get("/api/dashboard/events/99999")
    assert missing.status_code == 404


def test_dashboard_logs_filter_and_system_status(client, db_session, monkeypatch, tmp_path):
    log = _log(db_session, ip="198.51.100.9", risk="MEDIUM")
    detection = _detection(db_session, log, classification="suspicious", confidence=0.7)
    _analysis(db_session, detection, category="REPEATED_AUTHENTICATION_ATTEMPTS")
    _risk(db_session, detection, score=40, level="MEDIUM", action="ALERT")

    filtered = client.get("/api/dashboard/logs", params={"source_ip": "198.51.100", "classification": "suspicious"})
    assert filtered.status_code == 200
    payload = filtered.json()
    assert payload["count"] == 1
    assert payload["items"][0]["source_ip"] == "198.51.100.9"

    monkeypatch.setenv("ML_ARTIFACT_DIR", str(tmp_path / "missing-model"))
    status = client.get("/api/system/status").json()
    assert status["backend"]["status"] == "ok"
    assert status["database"]["status"] == "ok"
    assert status["ml_model"]["loaded"] is False
    assert status["ml_model"]["model_name"] is None
    assert status["collector"]["mode"] == "simulated_jsonl"
