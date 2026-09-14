from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.models import AttackLog, HoneypotEvent
from honeypot.parser.log_parser import (
    JsonlHoneypotParser,
    NormalizedEvent,
    compute_event_hash,
)

logger = logging.getLogger("intelligent_ids.collector")

COLLECTED_STATUS = "collected"
UNSCORED_RISK = "unscored"
SESSION_WINDOW = timedelta(
    minutes=int(os.getenv("COLLECTOR_SESSION_WINDOW_MINUTES", "30"))
)


@dataclass
class IngestOutcome:
    result: Literal["inserted", "duplicate"]
    event_hash: str
    attack_log_id: int


@dataclass
class ImportReport:
    file: str
    parsed: int = 0
    inserted: int = 0
    duplicates: int = 0
    rejected: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    attack_log_ids: list[int] = field(default_factory=list)
    inserted_log_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "parsed": self.parsed,
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "errors": self.errors,
            "attack_log_ids": self.attack_log_ids,
        }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _find_open_session(db: Session, event: NormalizedEvent) -> AttackLog | None:
    statement = (
        select(AttackLog)
        .where(
            AttackLog.ip_address == event.source_ip,
            AttackLog.status == COLLECTED_STATUS,
        )
        .order_by(AttackLog.timestamp.desc())
    )
    for log in db.scalars(statement):
        started = _as_utc(log.timestamp)
        if event.timestamp - started <= SESSION_WINDOW and event.timestamp >= started - timedelta(seconds=1):
            return log
    return None


def _apply_event_to_log(log: AttackLog, event: NormalizedEvent) -> None:
    if event.event_type == "login_attempt":
        log.attempts += 1
    elif event.event_type == "command" and event.command:
        commands = list(log.commands or [])
        commands.append(event.command)
        log.commands = commands
        flag_modified(log, "commands")


def _create_session_log(event: NormalizedEvent) -> AttackLog:
    return AttackLog(
        timestamp=event.timestamp,
        ip_address=event.source_ip,
        attempts=1 if event.event_type == "login_attempt" else 0,
        commands=[event.command] if event.event_type == "command" and event.command else [],
        status=COLLECTED_STATUS,
        risk_level=UNSCORED_RISK,
    )


def ingest_event(db: Session, event: NormalizedEvent) -> IngestOutcome:
    event_hash = compute_event_hash(event)
    existing = db.scalar(select(HoneypotEvent).where(HoneypotEvent.event_hash == event_hash))
    if existing is not None:
        logger.info(
            "Duplicate event detected hash=%s ip=%s type=%s",
            event_hash[:12],
            event.source_ip,
            event.event_type,
        )
        return IngestOutcome("duplicate", event_hash, existing.attack_log_id or 0)

    attack_log = _find_open_session(db, event)
    if attack_log is None:
        attack_log = _create_session_log(event)
        db.add(attack_log)
        db.flush()
    else:
        _apply_event_to_log(attack_log, event)

    record = HoneypotEvent(
        event_hash=event_hash,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        event_type=event.event_type,
        username=event.username,
        success=event.success,
        command=event.command,
        attack_log_id=attack_log.id,
    )
    db.add(record)
    try:
        db.commit()
        db.refresh(attack_log)
    except IntegrityError:
        db.rollback()
        duplicate = db.scalar(select(HoneypotEvent).where(HoneypotEvent.event_hash == event_hash))
        if duplicate is None:
            logger.exception("Event insert failed hash=%s", event_hash[:12])
            raise
        logger.info("Duplicate event detected hash=%s ip=%s", event_hash[:12], event.source_ip)
        return IngestOutcome("duplicate", event_hash, duplicate.attack_log_id or 0)
    except SQLAlchemyError:
        db.rollback()
        raise

    logger.info(
        "Event inserted hash=%s type=%s ip=%s log_id=%s",
        event_hash[:12],
        event.event_type,
        event.source_ip,
        attack_log.id,
    )
    return IngestOutcome("inserted", event_hash, attack_log.id)


def import_jsonl_file(db: Session, path: str | Path) -> ImportReport:
    log_path = Path(path)
    logger.info("Log file loaded path=%s", log_path)
    parser = JsonlHoneypotParser()
    events, failures = parser.parse_file(log_path)

    report = ImportReport(file=str(log_path), parsed=len(events), rejected=len(failures))
    report.errors = [{"line_number": item.line_number, "reason": item.reason} for item in failures]
    log_ids: set[int] = set()

    for event in events:
        outcome = ingest_event(db, event)
        log_ids.add(outcome.attack_log_id)
        if outcome.result == "inserted":
            report.inserted += 1
            if outcome.attack_log_id:
                report.inserted_log_ids.append(outcome.attack_log_id)
        else:
            report.duplicates += 1

    report.attack_log_ids = sorted(log_id for log_id in log_ids if log_id)
    logger.info(
        "Import completed file=%s parsed=%s inserted=%s duplicates=%s rejected=%s",
        log_path.name,
        report.parsed,
        report.inserted,
        report.duplicates,
        report.rejected,
    )
    return report
