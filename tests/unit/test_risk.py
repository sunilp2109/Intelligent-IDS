from ml.analysis.analyzer import analyze_activity
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.risk.decisions import recommend_action
from ml.risk.engine import assess_risk
from ml.risk.scorer import RiskInputError, get_risk_level
import pytest


def _features(**overrides) -> dict:
    body = {name: 0 for name in FEATURE_NAMES}
    body.update(
        {
            "total_events": 2,
            "login_attempts": 1,
            "successful_login_attempts": 1,
            "unique_username_count": 1,
            "unique_source_ip_count": 1,
            "session_duration_seconds": 45,
            "events_per_minute": 2.67,
        }
    )
    body.update(overrides)
    return body


def _brute_force_features() -> dict:
    return _features(
        total_events=23,
        login_attempts=20,
        failed_login_attempts=19,
        successful_login_attempts=1,
        failed_login_ratio=0.95,
        attempts_per_minute=12.0,
        command_count=3,
        unique_command_count=3,
        commands_per_minute=1.8,
        session_duration_seconds=100,
        events_per_minute=13.8,
        unique_username_count=2,
    )


def test_normal_activity_is_low_and_allow():
    features = _features()
    analysis = analyze_activity(features, {"classification": "normal", "confidence_score": 0.91})
    result = assess_risk(
        classification=analysis["classification"],
        confidence_score=analysis["ml_confidence"],
        attack_category=analysis["attack_category"],
        evidence_strength=analysis["evidence_strength"],
        features=analysis["features"],
        indicators=analysis["indicators"],
    )
    assert result["classification"] == "normal"
    assert result["attack_category"] == "NORMAL_ACTIVITY"
    assert 0 <= result["risk_score"] <= 24
    assert result["risk_level"] == "LOW"
    assert result["recommended_action"] == "ALLOW"
    assert result["operator_guidance"] == "MONITOR"
    assert result["execution_status"] == "recommendation_only"
    assert result["action_is_recommendation"] is True


def test_suspicious_activity_alerts_and_does_not_block():
    features = _features(
        total_events=6,
        login_attempts=6,
        failed_login_attempts=6,
        failed_login_ratio=1.0,
        attempts_per_minute=4.0,
        session_duration_seconds=90,
        events_per_minute=4.0,
    )
    analysis = analyze_activity(features, {"classification": "suspicious", "confidence_score": 0.72})
    result = assess_risk(
        classification="suspicious",
        confidence_score=0.72,
        attack_category=analysis["attack_category"],
        evidence_strength=analysis["evidence_strength"],
        features=features,
        indicators=analysis["indicators"],
    )
    assert result["classification"] == "suspicious"
    assert 25 <= result["risk_score"] <= 74
    assert result["risk_level"] in {"MEDIUM", "HIGH"}
    assert result["recommended_action"] == "ALERT"
    assert result["recommended_action"] != "BLOCK"


def test_malicious_brute_force_is_high_or_critical():
    features = _brute_force_features()
    analysis = analyze_activity(features, {"classification": "malicious", "confidence_score": 0.94})
    assert analysis["attack_category"] == "BRUTE_FORCE"
    result = assess_risk(
        classification="malicious",
        confidence_score=0.94,
        attack_category=analysis["attack_category"],
        evidence_strength=analysis["evidence_strength"],
        features=features,
        indicators=analysis["indicators"],
    )
    assert result["risk_score"] >= 75
    assert result["risk_level"] == "CRITICAL"
    assert result["recommended_action"] == "BLOCK"
    assert result["operator_guidance"] == "CONTAIN"
    assert result["execution_status"] == "recommendation_only"
    assert "BRUTE_FORCE" in result["decision_reason"][2]
    assert any("Failed-login ratio" in line for line in result["decision_reason"])


def test_high_confidence_scores_higher_than_low_confidence():
    features = _brute_force_features()
    analysis = analyze_activity(features, {"classification": "malicious", "confidence_score": 0.94})
    high = assess_risk(
        classification="malicious",
        confidence_score=0.94,
        attack_category=analysis["attack_category"],
        evidence_strength=analysis["evidence_strength"],
        features=features,
        indicators=analysis["indicators"],
    )
    low = assess_risk(
        classification="malicious",
        confidence_score=0.31,
        attack_category=analysis["attack_category"],
        evidence_strength=analysis["evidence_strength"],
        features=features,
        indicators=analysis["indicators"],
    )
    assert high["classification"] == "malicious"
    assert low["classification"] == "malicious"
    assert high["risk_score"] > low["risk_score"]
    assert high["risk_breakdown"]["confidence"] > low["risk_breakdown"]["confidence"]


def test_strong_evidence_scores_higher_than_weak_evidence():
    features = _brute_force_features()
    strong = assess_risk(
        classification="malicious",
        confidence_score=0.90,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
        features=features,
        indicators=["HIGH_FAILED_LOGIN_RATIO", "HIGH_LOGIN_ATTEMPT_RATE", "HIGH_LOGIN_ATTEMPTS"],
    )
    weak = assess_risk(
        classification="malicious",
        confidence_score=0.90,
        attack_category="BRUTE_FORCE",
        evidence_strength="LOW",
        features=features,
        indicators=["HIGH_LOGIN_ATTEMPTS"],
    )
    assert strong["risk_score"] > weak["risk_score"]
    assert strong["risk_breakdown"]["evidence_strength"] > weak["risk_breakdown"]["evidence_strength"]


def test_brute_force_category_outweighs_unknown_with_same_features():
    features = _brute_force_features()
    brute = assess_risk(
        classification="malicious",
        confidence_score=0.80,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
        features=features,
        indicators=["HIGH_FAILED_LOGIN_RATIO"],
    )
    unknown = assess_risk(
        classification="malicious",
        confidence_score=0.80,
        attack_category="UNKNOWN_SUSPICIOUS_ACTIVITY",
        evidence_strength="HIGH",
        features=features,
        indicators=["HIGH_FAILED_LOGIN_RATIO"],
    )
    assert brute["risk_breakdown"]["attack_category"] > unknown["risk_breakdown"]["attack_category"]
    assert unknown["risk_score"] >= 50
    assert unknown["attack_category"] == "UNKNOWN_SUSPICIOUS_ACTIVITY"


def test_suspicious_command_category():
    features = _features(
        total_events=5,
        login_attempts=1,
        successful_login_attempts=1,
        command_count=4,
        unique_command_count=2,
        repeated_command_count=2,
        suspicious_command_indicator=1,
        commands_per_minute=3.0,
        session_duration_seconds=80,
    )
    result = assess_risk(
        classification="suspicious",
        confidence_score=0.70,
        attack_category="SUSPICIOUS_COMMAND_ACTIVITY",
        evidence_strength="MEDIUM",
        features=features,
        indicators=["SUSPICIOUS_COMMAND_PATTERN", "REPEATED_COMMANDS"],
    )
    assert result["attack_category"] == "SUSPICIOUS_COMMAND_ACTIVITY"
    assert result["risk_level"] in {"MEDIUM", "HIGH"}
    assert result["recommended_action"] == "ALERT"
    assert any("Suspicious-command indicator is set" in line for line in result["decision_reason"])


def test_unknown_suspicious_activity_is_not_forced_low():
    result = assess_risk(
        classification="malicious",
        confidence_score=0.88,
        attack_category="UNKNOWN_SUSPICIOUS_ACTIVITY",
        evidence_strength="MEDIUM",
        features=_features(total_events=3, login_attempts=2, session_duration_seconds=40),
        indicators=[],
    )
    assert result["attack_category"] == "UNKNOWN_SUSPICIOUS_ACTIVITY"
    assert result["risk_score"] >= 25
    assert result["risk_level"] != "LOW"


def test_risk_score_boundaries_and_level_mapping():
    assert get_risk_level(0) == "LOW"
    assert get_risk_level(24) == "LOW"
    assert get_risk_level(25) == "MEDIUM"
    assert get_risk_level(49) == "MEDIUM"
    assert get_risk_level(50) == "HIGH"
    assert get_risk_level(74) == "HIGH"
    assert get_risk_level(75) == "CRITICAL"
    assert get_risk_level(100) == "CRITICAL"
    for score in (-5, 0, 24, 25, 50, 74, 75, 100, 140):
        level = get_risk_level(score)
        assert level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_decision_mapping():
    assert recommend_action("LOW")["recommended_action"] == "ALLOW"
    assert recommend_action("MEDIUM")["recommended_action"] == "ALERT"
    assert recommend_action("HIGH")["recommended_action"] == "ALERT"
    assert recommend_action("HIGH")["operator_guidance"] == "INVESTIGATE"
    assert recommend_action("CRITICAL")["recommended_action"] == "BLOCK"
    assert recommend_action("CRITICAL")["execution_status"] == "recommendation_only"


def test_low_confidence_suspicious_cannot_become_critical():
    result = assess_risk(
        classification="suspicious",
        confidence_score=0.20,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
        features=_brute_force_features(),
        indicators=[
            "HIGH_FAILED_LOGIN_RATIO",
            "HIGH_LOGIN_ATTEMPT_RATE",
            "HIGH_LOGIN_ATTEMPTS",
            "HIGH_FAILED_LOGIN_COUNT",
            "REPEATED_AUTHENTICATION_ATTEMPTS",
        ],
    )
    assert result["classification"] == "suspicious"
    assert result["risk_score"] <= 74
    assert result["risk_level"] != "CRITICAL"
    assert result["recommended_action"] != "BLOCK"


def test_normal_classification_does_not_become_critical():
    result = assess_risk(
        classification="normal",
        confidence_score=0.99,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
        features=_brute_force_features(),
        indicators=["HIGH_FAILED_LOGIN_RATIO", "HIGH_LOGIN_ATTEMPT_RATE"],
    )
    assert result["classification"] == "normal"
    assert result["risk_score"] <= 49
    assert result["risk_level"] in {"LOW", "MEDIUM"}
    assert result["recommended_action"] != "BLOCK"


def test_normal_override_caps_inflated_raw_score():
    from ml.risk.scorer import apply_score_overrides

    capped, applied = apply_score_overrides(
        90.0,
        classification="normal",
        confidence=0.99,
        attack_category="NORMAL_ACTIVITY",
        evidence_strength="LOW",
    )
    assert capped == 24.0
    assert "normal_classification_cap" in applied
    strong, strong_applied = apply_score_overrides(
        90.0,
        classification="normal",
        confidence=0.99,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
    )
    assert strong == 49.0
    assert "normal_classification_strong_evidence_cap" in strong_applied


def test_invalid_confidence():
    with pytest.raises(RiskInputError, match="between 0 and 1"):
        assess_risk(
            classification="malicious",
            confidence_score=1.5,
            attack_category="BRUTE_FORCE",
            evidence_strength="HIGH",
            features=_features(),
            indicators=[],
        )


def test_missing_classification():
    with pytest.raises(RiskInputError, match="classification is required"):
        assess_risk(
            classification="",
            confidence_score=0.9,
            attack_category="BRUTE_FORCE",
            evidence_strength="HIGH",
            features=_features(),
            indicators=[],
        )


def test_invalid_attack_category():
    with pytest.raises(RiskInputError, match="attack_category"):
        assess_risk(
            classification="malicious",
            confidence_score=0.9,
            attack_category="SQL_INJECTION",
            evidence_strength="HIGH",
            features=_features(),
            indicators=[],
        )


def test_risk_breakdown_sums_to_score():
    result = assess_risk(
        classification="malicious",
        confidence_score=0.94,
        attack_category="BRUTE_FORCE",
        evidence_strength="HIGH",
        features=_brute_force_features(),
        indicators=["HIGH_FAILED_LOGIN_RATIO", "HIGH_LOGIN_ATTEMPT_RATE"],
    )
    total = sum(result["risk_breakdown"].values())
    assert abs(total - result["risk_score"]) < 0.011
    assert 0 <= result["risk_score"] <= 100
    for key in ("classification", "confidence", "attack_category", "behavior", "evidence_strength", "override_adjustment"):
        assert key in result["risk_breakdown"]


def test_missing_feature_is_rejected():
    features = _features()
    features.pop("failed_login_ratio")
    with pytest.raises(RiskInputError, match="failed_login_ratio"):
        assess_risk(
            classification="normal",
            confidence_score=0.9,
            attack_category="NORMAL_ACTIVITY",
            evidence_strength="LOW",
            features=features,
            indicators=[],
        )
