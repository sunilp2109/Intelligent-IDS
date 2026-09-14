# Explainable AI with SHAP (Module 6)

Module 6 answers: **why did the trained Module 4 model classify this activity as normal, suspicious, or malicious?**

The explanation is calculated from the **actual trained Random Forest** and the **actual Module 3 feature values**. It is not hard-coded text, not an attack category, and not a risk score.

```
Feature Vector
      ↓
Preprocessing (same impute + scale used at prediction)
      ↓
Trained ML Model
      ↓
Prediction
      ↓
SHAP TreeExplainer
      ↓
Feature Contributions
      ↓
Human-readable Explanation
```

## What XAI means here

Explainable AI in this project is a **model-explanation** layer. SHAP estimates how each input feature contributed to the model's output for the predicted class.

SHAP does **not**:

- prove that an attack happened
- name a behavior such as brute force (that is Module 5)
- assign risk (later module)
- block an IP or change a firewall

## Why SHAP

The Module 4 detector is a scikit-learn **Random Forest**. Tree SHAP (`shap.TreeExplainer`) is the matching algorithm for that model: it uses the trees that were actually trained, rather than a second surrogate model.

This module does **not** train another classifier. It loads `ml/artifacts/intrusion_model.joblib`.

## Connection to the ML model

1. Validate the 15 Module 3 feature names.
2. Load the saved preprocessing+model pipeline.
3. Run `predict_proba` for class and confidence (same path as `POST /api/detection/predict`).
4. Transform the row with the pipeline's `preprocess` step only.
5. Explain the Random Forest with `TreeExplainer`.
6. Report contributions for the **predicted class**.

Feature names are never renamed. They stay:

`total_events`, `login_attempts`, `failed_login_attempts`, `successful_login_attempts`, `command_count`, `unique_command_count`, `failed_login_ratio`, `attempts_per_minute`, `commands_per_minute`, `unique_username_count`, `unique_source_ip_count`, `session_duration_seconds`, `events_per_minute`, `repeated_command_count`, `suspicious_command_indicator`

## SHAP vs attack analysis

| Layer | What it answers |
| --- | --- |
| Module 4 classification | Normal / suspicious / malicious |
| Module 4 confidence | Class probability from the Random Forest |
| Module 5 attack analysis | Heuristic behavior category and indicators |
| Module 6 SHAP | Feature contributions to the **model output** |

A high SHAP value on `failed_login_ratio` means that feature pushed the **model's predicted-class score**. It does not by itself mean "this was brute force." Module 5 may still label `BRUTE_FORCE` from thresholds.

## Multiclass explanations

The model has three classes. SHAP 0.52 for this Random Forest returns an array of shape `(samples, features, classes)`.

- Class order is `model.classes_` (the trained sklearn order), not a hard-coded list.
- The API explains the **predicted class**.
- A positive SHAP value increased that class's model output.
- A negative SHAP value decreased that class's model output.
- Positive is **not** assumed to mean malicious.

Where supported, `base_value` is the SHAP expected value for the explained class:

`model output ≈ base_value + sum(feature SHAP values)`

## Top features

Features are ranked by `abs(shap_value)`, default top 5. Signed values are kept so the direction is visible.

Wording is generated from those numbers, for example "contributed to the model's prediction." The code does not claim that a feature caused an attack.

## API

```
POST /api/explain
```

If no trained model artifact exists, the API returns HTTP 503:

`Trained model not found. Train the Module 4 model before generating explanations.`

Optional `detection_id` stores the structured JSON explanation on that Detection row. It does not create a second detection. Optional `log_id` without `detection_id` stores one Detection that already includes the explanation.

`POST /api/detection/predict` still does **not** run SHAP (SHAP is per-request and is only calculated from `/api/explain`).

## Offline global SHAP

Do not compute dataset-wide SHAP on every API call.

```powershell
python -m ml.scripts.shap_summary --dataset ml\data\raw\development_labeled_features.csv
```

This writes mean absolute SHAP over actual CSV rows. If that file is the synthetic development set, the output is labeled as development-only.

## How to test

From the project root, with the virtual environment active:

```powershell
pytest tests/test_explainability.py tests/test_explain_api.py -q
pytest -q
```

## Limitations

- Explains the trained model, not ground-truth causality
- Quality tracks the Module 4 training data (the development CSV is synthetic)
- Correlated features can split credit
- A SHAP explanation is not an attack verdict and not a risk score
- TreeExplainer is used because the current model is a Random Forest. A future non-tree model would need a different explainer.

## Security

This module only explains predictions. It does not execute commands, block IPs, or log credentials.
