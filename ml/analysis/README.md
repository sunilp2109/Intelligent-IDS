# Attack analysis (Module 5)

Module 5 interprets **behavioral evidence** after the ML model has classified a session.

```
ML classification + confidence
            +
Module 3 feature vector
            ↓
Attack analysis (heuristics)
            ↓
category, indicators, evidence
            ↓
Future XAI / risk engine
```

**ML classification ≠ attack category.**

- The Random Forest (Module 4) outputs `normal` / `suspicious` / `malicious` and a class probability (`ml_confidence`).
- Attack analysis does **not** re-predict that class. It reads the same feature values and applies documented rules to name a behavior category and list indicators.

SHAP/XAI is not implemented here. The original feature vector and `feature_names` are returned unchanged so Module 6 can explain the ML prediction later.

## Attack categories

| Category | When it is selected |
| --- | --- |
| `NORMAL_ACTIVITY` | ML class is `normal` (no attack type is forced) |
| `BRUTE_FORCE` | Many login attempts, many failures, high failed-login ratio |
| `REPEATED_AUTHENTICATION_ATTEMPTS` | Repeated logins without meeting the brute-force rule, or as a secondary category |
| `SUSPICIOUS_COMMAND_ACTIVITY` | Suspicious-command flag, repeated commands, or high command rate |
| `ABNORMAL_REQUEST_ACTIVITY` | High event frequency or short-duration high volume |
| `UNAUTHORIZED_ACCESS_ATTEMPT` | At least one successful login after several failures |
| `UNKNOWN_SUSPICIOUS_ACTIVITY` | ML is suspicious/malicious but no category rule matched |

A session may match more than one category. `attack_category` / `primary_category` is the highest-priority match. Others go in `secondary_categories`.

## Behavioral indicators

Indicators are raised only from Module 3 features:

`HIGH_LOGIN_ATTEMPTS`, `HIGH_FAILED_LOGIN_COUNT`, `HIGH_FAILED_LOGIN_RATIO`, `HIGH_LOGIN_ATTEMPT_RATE`, `REPEATED_AUTHENTICATION_ATTEMPTS`, `HIGH_COMMAND_RATE`, `REPEATED_COMMANDS`, `SUSPICIOUS_COMMAND_PATTERN`, `MULTIPLE_USERNAMES`, `MULTIPLE_SOURCE_IPS`, `HIGH_EVENT_FREQUENCY`, `SHORT_DURATION_HIGH_VOLUME`

Per-minute rates are ignored unless `session_duration_seconds` is at least 5, so a single event (Module 3 treats 0s duration as 1s → 60 events/min) is not treated as a high-rate flood.

## Thresholds

All numeric cut-offs live in `ml/analysis/thresholds.py` (`DEFAULT_THRESHOLDS`).

Examples: brute-force needs at least 8 attempts, 6 failures, and failed ratio ≥ 0.70.

These are **initial development heuristics**. They are not universally correct and must be validated experimentally.

## Evidence strength

`evidence_strength` is `LOW` / `MEDIUM` / `HIGH` from indicator/category counts. It is **not** an ML probability and is not a substitute for `ml_confidence`.

## API

```
POST /api/analysis/analyze
GET  /api/analysis/{detection_id}
GET  /api/analysis/thresholds
```

`GET /api/analysis/{detection_id}` rebuilds features from that detection’s AttackLog events, then runs the same `analyze_activity()` service.

## Limitations

- Heuristic categories can miss novel behavior (that is why `UNKNOWN_SUSPICIOUS_ACTIVITY` exists).
- Thresholds are not fitted to a labeled attack corpus.
- Analysis cannot invent packet/payload evidence that the honeypot did not store.
- If a Detection has no linked honeypot events, database lookup cannot reconstruct features.

## Future improvements

- Calibrate thresholds on labeled sessions
- Feed the preserved feature vector into SHAP
- Combine analysis + XAI in the dashboard
