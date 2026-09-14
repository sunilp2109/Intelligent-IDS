from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AttackLog(Base):
    __tablename__ = "attack_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    commands: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(64), nullable=False)
    honeypot_events: Mapped[list["HoneypotEvent"]] = relationship(
        back_populates="attack_log",
        cascade="all, delete-orphan",
    )


class HoneypotEvent(Base):
    """Raw normalized honeypot event used for deduplication and later Cowrie ingestion.

    AttackLog remains the aggregated activity record from Module 1. This table stores
    one row per unique source event so the same JSONL/Cowrie record is not imported twice.
    """

    __tablename__ = "honeypot_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_log_id: Mapped[int | None] = mapped_column(
        ForeignKey("attack_logs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    attack_log: Mapped[AttackLog | None] = relationship(back_populates="honeypot_events")
