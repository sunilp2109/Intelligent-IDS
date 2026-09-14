from ml.analysis.analyzer import analyze_activity
from ml.preprocessing.feature_extractor import extract_features
from tests.support import load_fixture


def _analyze(fixture_name: str, classification: str, confidence: float):
    events, failures = load_fixture(fixture_name)
    assert failures == []
    features = extract_features([event.to_dict() for event in events])
    result = analyze_activity(features, {"classification": classification, "confidence_score": confidence})
    result["features"] = features
    return result


def test_scenario_normal_activity():
    result = _analyze("normal_activity.jsonl", "normal", 0.91)
    assert result["attack_category"] == "NORMAL_ACTIVITY"
    assert result["features"]["login_attempts"] == 1
    assert result["features"]["failed_login_ratio"] == 0.0
    assert result["features"]["suspicious_command_indicator"] == 0


def test_scenario_brute_force_like_activity():
    result = _analyze("brute_force.jsonl", "malicious", 0.94)
    assert result["attack_category"] == "BRUTE_FORCE"
    assert result["features"]["login_attempts"] >= 10
    assert result["features"]["failed_login_ratio"] >= 0.75
    assert result["evidence_strength"] in {"MEDIUM", "HIGH"}


def test_scenario_suspicious_command_activity():
    result = _analyze("suspicious_commands.jsonl", "suspicious", 0.72)
    assert result["features"]["command_count"] >= 3
    assert result["features"]["repeated_command_count"] >= 1
    assert result["features"]["suspicious_command_indicator"] == 1
    assert result["attack_category"] in {
        "SUSPICIOUS_COMMAND_ACTIVITY",
        "UNKNOWN_SUSPICIOUS_ACTIVITY",
    }


def test_scenario_high_frequency_activity():
    result = _analyze("high_frequency.jsonl", "suspicious", 0.70)
    assert result["features"]["total_events"] >= 10
    assert result["features"]["session_duration_seconds"] <= 30
    assert result["features"]["events_per_minute"] > 10
    assert result["indicators"]


def test_scenario_mixed_activity_has_multiple_indicators():
    result = _analyze("mixed_activity.jsonl", "suspicious", 0.80)
    assert result["features"]["login_attempts"] >= 1
    assert result["features"]["command_count"] >= 1
    assert result["features"]["suspicious_command_indicator"] == 1
    assert len(result["indicators"]) >= 1
    if result["secondary_categories"]:
        assert result["attack_category"] not in result["secondary_categories"]


def test_scenario_unknown_suspicious_activity():
    result = _analyze("unknown_suspicious.jsonl", "suspicious", 0.66)
    assert result["attack_category"] == "UNKNOWN_SUSPICIOUS_ACTIVITY"
    assert result["insufficient_evidence_reason"]
    assert result["classification"] == "suspicious"
