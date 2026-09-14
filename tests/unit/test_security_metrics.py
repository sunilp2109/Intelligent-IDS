from ml.evaluation.evaluate import evaluate_predictions, one_vs_rest_rates


def test_malicious_one_vs_rest_rates_use_confusion_matrix():
    metrics = evaluate_predictions(
        ["normal", "normal", "suspicious", "malicious", "malicious", "malicious"],
        ["normal", "malicious", "suspicious", "malicious", "suspicious", "malicious"],
    )
    rates = one_vs_rest_rates(metrics, positive_class="malicious")
    assert rates["true_positive"] == 2
    assert rates["false_negative"] == 1
    assert rates["false_positive"] == 1
    assert rates["true_negative"] == 2
    assert abs(rates["false_positive_rate"] - (1 / 3)) < 1e-9
    assert abs(rates["false_negative_rate"] - (1 / 3)) < 1e-9
    assert rates["methodology"].startswith("one-vs-rest")
