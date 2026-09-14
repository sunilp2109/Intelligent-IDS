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


class FeatureVectorRecord(BaseModel):
    attack_log_id: int | None = None
    source_ip: str | None = None
    source_ips: list[str]
    session_start: str | None = None
    session_end: str | None = None
    features: dict[str, Any]
    feature_vector: list[float]


class FeatureExtractionResponse(BaseModel):
    count: int
    grouping: str
    feature_vectors: list[FeatureVectorRecord]


class FeatureExportResponse(BaseModel):
    file: str
    count: int


class DetectionPredictRequest(BaseModel):
    total_events: float
    login_attempts: float
    failed_login_attempts: float
    successful_login_attempts: float
    command_count: float
    unique_command_count: float
    failed_login_ratio: float
    attempts_per_minute: float
    commands_per_minute: float
    unique_username_count: float
    unique_source_ip_count: float
    session_duration_seconds: float
    events_per_minute: float
    repeated_command_count: float
    suspicious_command_indicator: float
    log_id: int | None = Field(default=None, ge=1)


class DetectionPredictResponse(BaseModel):
    classification: str
    confidence_score: float
    class_probabilities: dict[str, float]
    model_name: str | None = None
    model_version: str | None = None
    dataset_kind: str | None = None
    detection_id: int | None = None
    explanation: str | None = None


class DetectionRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    attack_log_id: int | None
    classification: str
    confidence_score: float
    explanation: str | None
    created_at: datetime
