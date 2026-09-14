# Risk assessment and decision engine (Module 7)

Module 7 answers: **how serious is this activity, and what should the operator do?**

It does **not** re-classify traffic, re-analyze behavior, or explain the model. Those remain Modules 4–6.

```
ML Prediction
      +
Attack Analysis
      +
Behavioral Features
      +
Evidence Strength
      ↓
Risk Assessment
      ↓
Risk Score
      ↓
Risk Level
      ↓
Decision Engine
      ↓
Recommended Action
```

## Purpose

Turn existing pipeline outputs into:

- a **risk score** (0–100 heuristic)
- a **risk level** (LOW / MEDIUM / HIGH / CRITICAL)
- a **recommended action** (ALLOW / ALERT / BLOCK)
- a **decision reason** built from the factors that actually contributed
- a **component breakdown** for later dashboard display

BLOCK is a **recommendation only**. This module never changes a firewall, blocks an IP, or runs a system command.

## Inputs

Values must come from Modules 3–5:

| Field | Source |
| --- | --- |
| `classification`, `confidence_score` | Module 4 |
| `attack_category`, `indicators`, `evidence_strength` | Module 5 |
| `features` | Module 3 (same 15 names) |

The engine does not invent these values and does not accept a client-supplied `risk_score`.

## Risk scoring formula

All weights live in `ml/risk/config.py` (`DEFAULT_RISK_CONFIG`). They are **initial project heuristics**, not a calibrated probability of harm.

```
unadjusted =
    classification_component
  + confidence_component
  + attack_category_component
  + behavior_component
  + evidence_strength_component

risk_score = round(clamp(apply_overrides(unadjusted), 0, 100))
```

The five component maxima are 30 + 20 + 25 + 15 + 10 = **100**, so no extra scaling is required before overrides.

`risk_breakdown.override_adjustment` is `risk_score - sum(the five components)`. After that field is included, the breakdown sums to the reported score (within rounding).

This is a **risk score**, not a probability of attack.

## Classification weights (max 30)

| Class | Points | Reason |
| --- | --- | --- |
| `normal` | 0 | Benign detector output should not inflate risk |
| `suspicious` | 15 | Real concern, not a confirmed malicious class |
| `malicious` | 30 | Strongest detector signal, still only 30% of the score |

## Confidence weighting (max 20)

```
confidence_component = 20 * ml_confidence * scale[classification]
```

| Class | Scale |
| --- | --- |
| `normal` | 0.0 |
| `suspicious` | 0.70 |
| `malicious` | 1.0 |

Confidence **never replaces** the ML class. `malicious` + 0.31 stays malicious; it only contributes fewer confidence points (6.2 instead of ~18.8 at 0.94). High confidence that a session is `normal` adds **zero** risk.

## Attack category weights (max 25)

| Category | Points | Reason |
| --- | --- | --- |
| `NORMAL_ACTIVITY` | 0 | No hostile pattern named |
| `REPEATED_AUTHENTICATION_ATTEMPTS` | 10 | Repeated logins without full brute-force evidence |
| `ABNORMAL_REQUEST_ACTIVITY` | 12 | Volume/rate anomaly |
| `UNKNOWN_SUSPICIOUS_ACTIVITY` | 14 | Not the lowest: ML already said suspicious/malicious |
| `SUSPICIOUS_COMMAND_ACTIVITY` | 16 | Hostile commands on a honeypot |
| `BRUTE_FORCE` | 20 | Concentrated failed authentication |
| `UNAUTHORIZED_ACCESS_ATTEMPT` | 25 | At least one success after failures |

These are project weights, not industry CVSS scores.

## Behavioral evidence (max 15)

Uses Module 3 **values** and Module 5 **indicator names**. It does not re-run feature extraction.

1. Sum documented points for each supplied indicator (cap 10).
2. Add intensity from existing features:
   - failed-login ratio (if `login_attempts >= 3`)
   - attempts/commands/events per minute only if `session_duration_seconds >= 5` (same floor as Module 5, so a 1-second session is not treated as 60/min)

Then clamp to 15.

## Evidence strength (max 10)

| Strength | Points |
| --- | --- |
| `LOW` | 2 |
| `MEDIUM` | 6 |
| `HIGH` | 10 |

If classification is `normal` and category is `NORMAL_ACTIVITY`, this component is **0** so leftover LOW evidence does not mark ordinary sessions as risky.

## Risk thresholds

`get_risk_level(score)`:

| Score | Level |
| --- | --- |
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

Thresholds are configurable on `RiskConfig`.

## Score overrides

Applied after the unadjusted sum. They cap the score; they do **not** rewrite the ML class.

- `normal` → cap 24 (LOW), unless evidence is HIGH and the category is not `NORMAL_ACTIVITY`, then cap 49 (MEDIUM). Normal never becomes CRITICAL.
- `suspicious` + confidence < 0.50 → cap 74 (cannot become CRITICAL from weak confidence).
- `malicious` + confidence < 0.50 + evidence not HIGH → cap 74.

## Decision mapping

Kept separate from scoring. Always `execution_status = recommendation_only`.

| Risk level | `recommended_action` | `operator_guidance` |
| --- | --- | --- |
| LOW | ALLOW | MONITOR |
| MEDIUM | ALERT | MONITOR |
| HIGH | ALERT | INVESTIGATE |
| CRITICAL | BLOCK | CONTAIN |

Suspicious/medium traffic is alerted, not blocked. BLOCK means “recommend contain,” not “change the firewall.”

## Decision reason vs SHAP

| Output | Meaning |
| --- | --- |
| Module 4 confidence | Class probability from the Random Forest |
| Module 6 SHAP | Why the **model** produced that class |
| Module 7 decision reason | Why this **risk score / action** was recommended |

Reasons are generated from the actual class, confidence, category, indicators, feature values, and any caps that fired.

## API

```
GET  /api/risk/thresholds
POST /api/risk/assess
GET  /api/risk/{detection_id}
```

`POST /api/risk/assess` scores the supplied Module 4–5 fields. Optional `detection_id` stores a `RiskAssessment` row.

`GET /api/risk/{detection_id}` loads the Detection, uses the latest AttackAnalysis (or runs Module 5 if none exists), then scores and stores the result.

## Example scenarios

**Normal:** `normal` + `NORMAL_ACTIVITY` + low evidence → LOW → ALLOW / MONITOR.

**Suspicious:** `suspicious` + moderate indicators → typically MEDIUM → ALERT / MONITOR (not BLOCK).

**Malicious brute force:** `malicious` + high confidence + `BRUTE_FORCE` + HIGH evidence → HIGH or CRITICAL → ALERT/INVESTIGATE or BLOCK/CONTAIN recommendation.

**Unknown suspicious:** `UNKNOWN_SUSPICIOUS_ACTIVITY` still uses ML class, confidence, behavior, and evidence. It is not forced to the lowest score.

## Limitations

- Weights are not statistically calibrated.
- Risk is not P(attack).
- Quality tracks Modules 3–5; garbage in still yields a number.
- Caps are project safeguards, not legal policy.
- No automated response is implemented.

## How to test

```powershell
pytest tests/test_risk_engine.py tests/test_risk_api.py -q
pytest -q
```
