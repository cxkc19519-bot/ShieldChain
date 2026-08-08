from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WazuhAlertInput(StrictModel):
    """Minimum normalized evidence accepted from the Manager-side adapter."""

    external_id: str = Field(min_length=1, max_length=256)
    occurred_at: datetime
    severity: int = Field(ge=0, le=15)
    rule_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    agent_id: str | None = Field(default=None, max_length=128)
    agent_name: str | None = Field(default=None, max_length=256)
    mitre_ids: tuple[str, ...] = Field(default=(), max_length=32)
    process_name: str | None = Field(default=None, max_length=512)
    parent_process_name: str | None = Field(default=None, max_length=512)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value.astimezone(UTC)

    @field_validator("mitre_ids")
    @classmethod
    def validate_mitre_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(dict.fromkeys(item.strip() for item in value))
        if any(not item or len(item) > 32 for item in cleaned):
            raise ValueError("mitre_ids contains an invalid value")
        return cleaned


class WazuhReviewCaseView(StrictModel):
    id: UUID
    tracking_id: str
    alert_id: UUID
    source: Literal["wazuh"] = "wazuh"
    status: Literal["needs_review"] = "needs_review"
    severity: int
    rule_id: str
    title: str
    endpoint: str
    created_at: datetime
    updated_at: datetime


class WazuhAlertView(StrictModel):
    id: UUID
    external_id: str
    occurred_at: datetime
    severity: int
    rule_id: str
    title: str
    agent_name: str | None
    mitre_ids: tuple[str, ...]
    process_name: str | None
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    received_at: datetime
    created: bool = True
    review_case: WazuhReviewCaseView | None = None


class WazuhAlertListResponse(StrictModel):
    items: list[WazuhAlertView]


class WazuhReviewCaseListResponse(StrictModel):
    items: list[WazuhReviewCaseView]
