from __future__ import annotations

from typing import Any

DEFAULT_TOP_FEATURES = 5
INCREASES = "increases_prediction"
DECREASES = "decreases_prediction"
NO_EFFECT = "no_effect"

LIMITATIONS = (
    "SHAP explains model behavior, not real-world causality.",
    "A large SHAP value does not prove that an attack occurred.",
    "Explanations depend on the trained Module 4 model and its feature representation.",
    "Correlated features can share or split credit, so one feature may look more or less important than it is.",
    "SHAP does not identify attack categories; Module 5 does that separately.",
)


def contribution_direction(shap_value: float) -> str:
    if shap_value > 0:
        return INCREASES
    if shap_value < 0:
        return DECREASES
    return NO_EFFECT


def rank_feature_contributions(
    contributions: list[dict[str, Any]],
    *,
    top_n: int = DEFAULT_TOP_FEATURES,
) -> list[dict[str, Any]]:
    ranked = sorted(
        contributions,
        key=lambda item: abs(float(item["shap_value"])),
        reverse=True,
    )
    limit = max(0, min(int(top_n), len(ranked)))
    return ranked[:limit]


def _signed(value: float) -> str:
    return f"{value:+.4f}"


def build_summary_text(
    *,
    classification: str,
    explained_class: str,
    top_features: list[dict[str, Any]],
) -> str:
    lines = [
        f"Prediction: {classification.upper()}",
        f"Explained class: {explained_class}",
        "",
        "Top contributing factors:",
    ]
    if not top_features:
        lines.append("No feature contributions were available.")
    for index, item in enumerate(top_features, start=1):
        shap_value = float(item["shap_value"])
        direction = item.get("direction") or contribution_direction(shap_value)
        if direction == INCREASES:
            effect = f"Increased the model's {explained_class} prediction"
        elif direction == DECREASES:
            effect = f"Decreased the model's {explained_class} prediction"
        else:
            effect = f"Did not change the model's {explained_class} prediction"
        lines.extend(
            [
                f"{index}. {item['feature']}",
                f"   Value: {item['value']}",
                f"   Contribution: {_signed(shap_value)}",
                f"   Effect: {effect}",
                "   This feature contributed to the model's prediction; it did not cause an attack.",
            ]
        )
    lines.extend(
        [
            "",
            "SHAP explains how the trained model used these features. It is not proof of real-world causality.",
        ]
    )
    return "\n".join(lines)


def format_explanation(
    *,
    classification: str,
    confidence_score: float,
    explained_class: str,
    base_value: float,
    model_output: float,
    contributions: list[dict[str, Any]],
    top_n: int = DEFAULT_TOP_FEATURES,
    shap_version: str,
    explainer_type: str,
    model_type: str,
    base_values_by_class: dict[str, float] | None = None,
) -> dict[str, Any]:
    ranked = rank_feature_contributions(contributions, top_n=top_n)
    visual_data = [
        {
            "feature": item["feature"],
            "shap_value": item["shap_value"],
            "absolute_shap_value": item["absolute_shap_value"],
            "value": item["value"],
            "direction": item["direction"],
        }
        for item in contributions
    ]
    return {
        "prediction": classification,
        "model_confidence": confidence_score,
        "explained_class": explained_class,
        "base_value": base_value,
        "model_output": model_output,
        "base_values_by_class": base_values_by_class or {},
        "top_features": ranked,
        "feature_contributions": contributions,
        "visual_data": visual_data,
        "summary_text": build_summary_text(
            classification=classification,
            explained_class=explained_class,
            top_features=ranked,
        ),
        "shap_version": shap_version,
        "explainer_type": explainer_type,
        "model_type": model_type,
        "limitations": list(LIMITATIONS),
        "notes": (
            "SHAP feature contributions explain the Module 4 model output for the predicted class. "
            "They are not an attack-category label and are not a risk score."
        ),
    }
