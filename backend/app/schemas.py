from datetime import datetime
from ipaddress import ip_address as parse_ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AttackLogCreate(BaseModel):
    timestamp: datetime | None = None
    ip_address: str = Field(..., min_length=1, max_length=64)
    attempts: int = Field(..., ge=0)
    commands: list[str] = Field(default_factory=list)
    status: str = Field(..., min_length=1, max_length=64)
    risk_level: str = Field(..., min_length=1, max_length=64)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            parse_ip_address(value)
        except ValueError as exc:
            raise ValueError("ip_address must be a valid IPv4 or IPv6 address") from exc
        return value

    @field_validator("status", "risk_level")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be empty")
        return cleaned


class AttackLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    ip_address: str
    attempts: int
    commands: list[str]
    status: str
    risk_level: str


class HoneypotEventIn(BaseModel):
    timestamp: datetime
    source_ip: str = Field(..., min_length=1, max_length=64)
    event_type: str = Field(..., min_length=1, max_length=64)
    username: str | None = None
    success: bool | None = None
    command: str | None = None

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        try:
            parse_ip_address(value)
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc
        return value


class IngestEventResponse(BaseModel):
    result: Literal["inserted", "duplicate"]
    event_hash: str
    attack_log_id: int
    attack_log: AttackLogResponse


class ImportRequest(BaseModel):
    path: str | None = None


class ImportReportResponse(BaseModel):
    file: str
    parsed: int
    inserted: int
    duplicates: int
    rejected: int
    errors: list[dict[str, Any]]
    attack_log_ids: list[int]
