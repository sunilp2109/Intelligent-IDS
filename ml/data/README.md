# ML data

## Current honeypot feature data

`../sample_features.csv` is unlabeled. It is produced by Module 3 from simulated honeypot events and **cannot** be used to train a supervised detector.

Place labeled CSVs in `raw/`. Processed copies may be written to `processed/`.

## Required labeled format

CSV columns:

```
total_events,login_attempts,failed_login_attempts,successful_login_attempts,command_count,unique_command_count,failed_login_ratio,attempts_per_minute,commands_per_minute,unique_username_count,unique_source_ip_count,session_duration_seconds,events_per_minute,repeated_command_count,suspicious_command_indicator,label
```

`label` must be one of: `normal`, `suspicious`, `malicious`.

Copy `raw/labeled_features.template.csv` and add rows from a legitimate source.

## Development dataset

`raw/development_labeled_features.csv` is a **small synthetic development set**.

- Features are calculated by the Module 3 extractor.
- Labels describe how each synthetic session was constructed (`normal`, `suspicious`, or `malicious`).
- It exists only so the training/prediction pipeline can be tested.
- It is **not** real attacker ground truth and must not be reported as final IDS experimental results.

## Importing a public dataset later

Keep public datasets (for example CIC-IDS or UNSW-NB15) as separate files in `raw/`. Map their classes onto `normal` / `suspicious` / `malicious` in a documented conversion script. Do not mix unlabeled honeypot rows with those labels unless an analyst has labeled them.
