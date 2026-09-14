"""Batch-import simulated honeypot JSONL logs into the AttackLog database."""

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
from app.services.ingestion import import_jsonl_file  # noqa: E402

DEFAULT_LOG = ROOT / "honeypot" / "logs" / "sample_events.jsonl"


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Import controlled honeypot JSONL events into the Intelligent IDS database."
    )
    parser.add_argument(
        "--file",
        default=str(DEFAULT_LOG),
        help="Path to a JSONL honeypot log (default: honeypot/logs/sample_events.jsonl)",
    )
    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.is_file():
        print(f"Log file not found: {log_path}", file=sys.stderr)
        return 1

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        report = import_jsonl_file(db, log_path)
    finally:
        db.close()

    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.rejected == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
