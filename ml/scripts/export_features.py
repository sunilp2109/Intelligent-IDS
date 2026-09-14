"""Export calculated behavioral feature vectors to CSV."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import AttackLog, HoneypotEvent  # noqa: E402, F401
from app.services.features import extract_features_from_db  # noqa: E402
from honeypot.parser.log_parser import JsonlHoneypotParser  # noqa: E402
from ml.preprocessing.feature_extractor import (  # noqa: E402
    extract_session_features,
    write_features_csv,
)

DEFAULT_OUTPUT = ROOT / "ml" / "data" / "features.csv"
SAMPLE_LOG = ROOT / "honeypot" / "logs" / "sample_events.jsonl"
SAMPLE_OUTPUT = ROOT / "ml" / "data" / "sample_features.csv"


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    parser = argparse.ArgumentParser(description="Export Intelligent IDS behavioral feature vectors to CSV.")
    parser.add_argument("--file", default=str(DEFAULT_OUTPUT), help="Output CSV path.")
    parser.add_argument(
        "--from-sample",
        action="store_true",
        help="Calculate features from honeypot/logs/sample_events.jsonl instead of the database.",
    )
    parser.add_argument("--source-ip", default=None)
    parser.add_argument("--log-id", type=int, default=None)
    args = parser.parse_args()

    if args.from_sample:
        events, failures = JsonlHoneypotParser().parse_file(SAMPLE_LOG)
        records = extract_session_features(events)
        output = Path(args.file) if args.file != str(DEFAULT_OUTPUT) else SAMPLE_OUTPUT
        write_features_csv(records, output)
        print(
            json.dumps(
                {
                    "file": str(output),
                    "count": len(records),
                    "rejected_raw_lines": len(failures),
                    "source": str(SAMPLE_LOG),
                },
                indent=2,
            )
        )
        return 0

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        records = extract_features_from_db(db, source_ip=args.source_ip, log_id=args.log_id)
    finally:
        db.close()

    output = write_features_csv(records, args.file)
    print(json.dumps({"file": str(output), "count": len(records)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
