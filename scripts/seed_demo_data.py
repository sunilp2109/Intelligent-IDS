"""Insert labeled DEMO records for dashboard layout checks.

This script does NOT run automatically. It does NOT train a model or compute
SHAP values. Records are marked status=demo so they are distinguishable from
collector-ingested activity.

Usage (from project root, venv active):

    python -m scripts.seed_demo_data
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import select

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import AttackAnalysis, AttackLog, Detection, HoneypotEvent, RiskAssessment  # noqa: E402

DEMO_NOTE = "DEMO/TEST seed record. Not a live detection."


def _hash(*parts: object) -> str:
    return "demo-" + "-".join(str(part).replace(":", "") for part in parts)


def seed() -> dict[str, int]:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    created = {"logs": 0, "events": 0, "detections": 0}
    now = datetime.now(timezone.utc)
    rows = [
        {
            "ip": "192.0.2.10",
            "classification": "normal",
            "confidence": 0.91,
            "category": "NORMAL_ACTIVITY",
            "strength": "LOW",
            "score": 6,
            "level": "LOW",
            "action": "ALLOW",
            "guidance": "MONITOR",
            "indicators": [],
        },
        {
            "ip": "192.0.2.20",
            "classification": "suspicious",
            "confidence": 0.72,
            "category": "REPEATED_AUTHENTICATION_ATTEMPTS",
            "strength": "MEDIUM",
            "score": 48,
            "level": "MEDIUM",
            "action": "ALERT",
            "guidance": "MONITOR",
            "indicators": ["HIGH_FAILED_LOGIN_RATIO", "REPEATED_AUTHENTICATION_ATTEMPTS"],
        },
        {
            "ip": "192.0.2.30",
            "classification": "malicious",
            "confidence": 0.94,
            "category": "BRUTE_FORCE",
            "strength": "HIGH",
            "score": 87,
            "level": "CRITICAL",
            "action": "BLOCK",
            "guidance": "CONTAIN",
            "indicators": ["HIGH_FAILED_LOGIN_RATIO", "HIGH_LOGIN_ATTEMPT_RATE"],
        },
    ]
    try:
        for index, row in enumerate(rows):
            existing = db.scalars(
                select(AttackLog).where(AttackLog.ip_address == row["ip"], AttackLog.status == "demo")
            ).first()
            if existing is not None:
                continue
            stamp = now - timedelta(hours=index)
            log = AttackLog(
                timestamp=stamp,
                ip_address=row["ip"],
                attempts=4 if row["classification"] != "malicious" else 20,
                commands=["ls"] if row["classification"] != "malicious" else [],
                status="demo",
                risk_level=row["level"],
            )
            db.add(log)
            db.flush()
            event = HoneypotEvent(
                event_hash=_hash(row["ip"], stamp.isoformat()),
                timestamp=stamp,
                source_ip=row["ip"],
                event_type="login_attempt",
                username="demo",
                success=row["classification"] == "normal",
                command=None,
                attack_log_id=log.id,
            )
            db.add(event)
            detection = Detection(
                attack_log_id=log.id,
                classification=row["classification"],
                confidence_score=row["confidence"],
                explanation=None,
            )
            db.add(detection)
            db.flush()
            db.add(
                AttackAnalysis(
                    detection_id=detection.id,
                    attack_category=row["category"],
                    primary_indicator=row["indicators"][0] if row["indicators"] else row["category"],
                    indicators=row["indicators"],
                    secondary_categories=[],
                    evidence={"note": DEMO_NOTE},
                    evidence_strength=row["strength"],
                    features={"login_attempts": log.attempts},
                    insufficient_evidence_reason=None,
                )
            )
            db.add(
                RiskAssessment(
                    detection_id=detection.id,
                    risk_score=row["score"],
                    risk_level=row["level"],
                    recommended_action=row["action"],
                    operator_guidance=row["guidance"],
                    execution_status="recommendation_only",
                    decision_reason=[DEMO_NOTE, f"Seeded {row['classification']} example"],
                    risk_breakdown={
                        "classification": 0 if row["classification"] == "normal" else 15,
                        "confidence": 0,
                        "attack_category": 0,
                        "behavior": 0,
                        "evidence_strength": 0,
                        "override_adjustment": 0,
                    },
                    overrides_applied=[],
                    inputs_snapshot={"classification": row["classification"], "note": DEMO_NOTE},
                )
            )
            created["logs"] += 1
            created["events"] += 1
            created["detections"] += 1
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return created


def main() -> int:
    created = seed()
    print("Inserted labeled DEMO records (status=demo). SHAP explanations were not fabricated.")
    print(created)
    print("This script is optional and is not run by the API.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
