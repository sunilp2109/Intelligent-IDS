import pandas as pd
import pytest

from ml.explainability.explanation_formatter import (
    contribution_direction,
    rank_feature_contributions,
)
from ml.explainability.shap_explainer import (
    ExplanationError,
    ExplanationUnavailableError,
    MISSING_MODEL_MESSAGE,
    clear_explainer_cache,
    create_explainer,
    explain_features,
    get_explainer,
    load_pipeline_and_model,
)
from ml.explainability.summary import compute_global_shap_importance
from ml.models.config import LABELS
from ml.models.predict import InvalidFeatureInputError
from ml.models.train import train_and_save
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.scripts.build_development_dataset import build_development_rows
from sklearn.linear_model import LogisticRegression


def _frame():
    return pd.DataFrame(build_development_rows(per_class=8))


def _train(tmp_path):
    dataset = tmp_path / "dev.csv"
    _frame().to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    clear_explainer_cache()
    return dataset


def _sample(**overrides):
    body = {name: float(_frame().iloc[-1][name]) for name in FEATURE_NAMES}
    body.update(overrides)
    return body


def test_missing_model_artifact(tmp_path):
    with pytest.raises(ExplanationUnavailableError, match="Trained model not found"):
        explain_features(_sample(), directory=tmp_path / "missing")


def test_missing_model_message_is_explicit(tmp_path):
    with pytest.raises(ExplanationUnavailableError) as exc:
        get_explainer(tmp_path / "missing")
    assert str(exc.value) == MISSING_MODEL_MESSAGE


def test_model_loading_and_explainer_creation(tmp_path):
    _train(tmp_path)
    pipeline, model, names = load_pipeline_and_model(tmp_path)
    assert names == list(FEATURE_NAMES)
    explainer = create_explainer(model)
    assert type(explainer).__name__ == "TreeExplainer"
    loaded = get_explainer(tmp_path)
    assert type(loaded).__name__ == "TreeExplainer"
    assert pipeline.named_steps["model"] is model


def test_non_tree_model_is_rejected():
    with pytest.raises(ExplanationError, match="Unsupported model type"):
        create_explainer(LogisticRegression())


def test_single_prediction_explanation(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path)
    explanation = result["explanation"]
    assert result["classification"] in LABELS
    assert explanation["explained_class"] == result["classification"]
    assert explanation["prediction"] == result["classification"]
    assert 0.0 <= result["confidence_score"] <= 1.0
    assert isinstance(explanation["base_value"], float)
    reconstructed = explanation["base_value"] + sum(
        item["shap_value"] for item in explanation["feature_contributions"]
    )
    assert abs(reconstructed - explanation["model_output"]) < 1e-6


def test_multiclass_explanation_uses_predicted_class(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path)
    explanation = result["explanation"]
    assert set(explanation["base_values_by_class"]) == set(LABELS)
    assert explanation["explained_class"] == result["classification"]
    assert result["classification"] in result["class_probabilities"]


def test_feature_names_preserved(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path)
    names = [item["feature"] for item in result["explanation"]["feature_contributions"]]
    assert names == list(FEATURE_NAMES)
    assert {item["feature"] for item in result["explanation"]["top_features"]}.issubset(set(FEATURE_NAMES))


def test_shap_values_are_numeric(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path)
    contributions = result["explanation"]["feature_contributions"]
    assert len(contributions) == len(FEATURE_NAMES)
    for item in contributions:
        assert isinstance(item["shap_value"], float)
        assert isinstance(item["value"], float)
        assert item["absolute_shap_value"] == abs(item["shap_value"])
        assert item["shap_value"] == item["shap_value"]  # not NaN


def test_top_feature_ranking_uses_absolute_value():
    contributions = [
        {"feature": "a", "value": 1, "shap_value": 0.10, "absolute_shap_value": 0.10, "direction": "increases_prediction"},
        {"feature": "b", "value": 1, "shap_value": -0.40, "absolute_shap_value": 0.40, "direction": "decreases_prediction"},
        {"feature": "c", "value": 1, "shap_value": 0.20, "absolute_shap_value": 0.20, "direction": "increases_prediction"},
    ]
    ranked = rank_feature_contributions(contributions, top_n=2)
    assert [item["feature"] for item in ranked] == ["b", "c"]


def test_top_features_from_actual_shap(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path, top_n=5)
    top = result["explanation"]["top_features"]
    assert len(top) == 5
    abs_values = [item["absolute_shap_value"] for item in top]
    assert abs_values == sorted(abs_values, reverse=True)


def test_positive_and_negative_contribution_handling():
    assert contribution_direction(0.31) == "increases_prediction"
    assert contribution_direction(-0.04) == "decreases_prediction"
    assert contribution_direction(0.0) == "no_effect"


def test_actual_shap_direction_matches_sign(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path)
    directions = {item["direction"] for item in result["explanation"]["feature_contributions"]}
    for item in result["explanation"]["feature_contributions"]:
        if item["shap_value"] > 0:
            assert item["direction"] == "increases_prediction"
        elif item["shap_value"] < 0:
            assert item["direction"] == "decreases_prediction"
        else:
            assert item["direction"] == "no_effect"
    assert "increases_prediction" in directions or "decreases_prediction" in directions


def test_missing_feature(tmp_path):
    _train(tmp_path)
    with pytest.raises(InvalidFeatureInputError, match="Missing required feature"):
        explain_features({"total_events": 1}, directory=tmp_path)


def test_invalid_feature_value(tmp_path):
    _train(tmp_path)
    payload = _sample(login_attempts="nope")
    with pytest.raises(InvalidFeatureInputError, match="must be numeric"):
        explain_features(payload, directory=tmp_path)
    payload = _sample(failed_login_ratio=float("nan"))
    with pytest.raises(InvalidFeatureInputError, match="NaN"):
        explain_features(payload, directory=tmp_path)


def test_human_readable_text_comes_from_shap(tmp_path):
    _train(tmp_path)
    result = explain_features(_sample(), directory=tmp_path, top_n=3)
    text = result["explanation"]["summary_text"]
    assert result["classification"].upper() in text
    assert "contributed to the model's prediction" in text
    assert "caused the attack" not in text
    for item in result["explanation"]["top_features"]:
        assert item["feature"] in text


def test_global_shap_summary_uses_actual_rows(tmp_path):
    dataset = _train(tmp_path)
    summary = compute_global_shap_importance(directory=tmp_path, dataset_file=dataset, max_rows=24)
    assert summary["rows_explained"] == 24
    names = [item["feature"] for item in summary["global_feature_importance"]]
    assert set(names) == set(FEATURE_NAMES)
    assert names == [item["feature"] for item in sorted(summary["global_feature_importance"], key=lambda row: row["mean_abs_shap"], reverse=True)]
    for label in LABELS:
        assert label in summary["feature_importance_by_class"]
        assert all(isinstance(item["mean_abs_shap"], float) for item in summary["feature_importance_by_class"][label])
