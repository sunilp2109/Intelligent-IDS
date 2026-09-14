import pandas as pd
import pytest

from ml.evaluation.evaluate import evaluate_predictions
from ml.models.config import LABELS
from ml.models.predict import InvalidFeatureInputError, predict_features
from ml.models.train import train_and_save
from ml.preprocessing.dataset import (
    DatasetValidationError,
    prepare_xy,
    split_data,
    validate_dataset,
)
from ml.preprocessing.feature_schema import FEATURE_NAMES
from ml.preprocessing.preprocessor import build_preprocessor, features_to_frame
from ml.scripts.build_development_dataset import build_development_rows


def _valid_frame() -> pd.DataFrame:
    return pd.DataFrame(build_development_rows(per_class=8))


def test_dataset_validation_accepts_labeled_features():
    report = validate_dataset(_valid_frame())
    assert report.samples == 24
    assert report.classes["normal"] == 8
    assert report.classes["suspicious"] == 8
    assert report.classes["malicious"] == 8
    assert report.missing_values == 0
    assert report.invalid_values == 0


def test_missing_required_feature():
    frame = _valid_frame().drop(columns=["failed_login_ratio"])
    with pytest.raises(DatasetValidationError, match="failed_login_ratio"):
        validate_dataset(frame)


def test_missing_label():
    frame = _valid_frame().drop(columns=["label"])
    with pytest.raises(DatasetValidationError, match="label"):
        validate_dataset(frame)


def test_invalid_numeric_value_is_reported():
    frame = _valid_frame()
    frame.loc[0, "attempts_per_minute"] = float("inf")
    report = validate_dataset(frame)
    assert report.invalid_values >= 1
    assert any("infinite" in issue.lower() for issue in report.issues)


def test_train_test_split_has_no_leakage():
    features, labels = prepare_xy(_valid_frame())
    x_train, x_test, y_train, y_test = split_data(features, labels)
    assert set(x_train.index).isdisjoint(x_test.index)
    assert len(x_train) + len(x_test) == len(features)
    assert set(y_train.unique()).issubset(set(LABELS))
    assert set(y_test.unique()).issubset(set(LABELS))


def test_preprocessing_replaces_missing_with_finite_values():
    frame = _valid_frame()
    frame.loc[0, "command_count"] = float("nan")
    features, _labels = prepare_xy(frame)
    transformed = build_preprocessor().fit_transform(features)
    assert transformed.shape[1] == len(FEATURE_NAMES)
    assert (transformed == transformed).all()


def test_train_save_load_and_predict(tmp_path):
    dataset = tmp_path / "dev.csv"
    _valid_frame().to_csv(dataset, index=False)
    result = train_and_save(dataset, output_dir=tmp_path)
    assert result["trained"] is True
    assert (tmp_path / "intrusion_model.joblib").is_file()
    assert (tmp_path / "model_registry.json").is_file()

    metrics = result["metrics"]
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert "macro_avg" in metrics
    assert "confusion_matrix" in metrics
    assert result["feature_importance"][0]["feature"] in FEATURE_NAMES

    sample = {name: float(_valid_frame().iloc[0][name]) for name in FEATURE_NAMES}
    prediction = predict_features(sample, directory=tmp_path)
    assert prediction["classification"] in LABELS
    assert 0.0 <= prediction["confidence_score"] <= 1.0
    assert abs(sum(prediction["class_probabilities"].values()) - 1.0) < 1e-6


def test_invalid_feature_input_for_prediction(tmp_path):
    dataset = tmp_path / "dev.csv"
    _valid_frame().to_csv(dataset, index=False)
    train_and_save(dataset, output_dir=tmp_path)
    with pytest.raises(InvalidFeatureInputError, match="Missing required feature"):
        predict_features({"total_events": 1}, directory=tmp_path)


def test_evaluation_metrics_shape():
    y_true = ["normal", "suspicious", "malicious", "normal"]
    y_pred = ["normal", "suspicious", "suspicious", "normal"]
    metrics = evaluate_predictions(y_true, y_pred)
    assert set(metrics["per_class"]) == set(LABELS)
    assert metrics["confusion_matrix"]["matrix"][0][0] == 2


def test_features_to_frame_rejects_non_numeric_as_nan():
    frame = features_to_frame({name: 1 for name in FEATURE_NAMES} | {"login_attempts": "nope"})
    assert frame.loc[0, "login_attempts"] != frame.loc[0, "login_attempts"]
