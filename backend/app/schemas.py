from datetime import datetime
from ipaddress import ip_address as parse_ip_address

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
