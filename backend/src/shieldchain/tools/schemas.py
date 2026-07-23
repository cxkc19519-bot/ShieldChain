"""Public-safe schemas for trusted-tool traces and controls."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ToolDecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: str = Field(pattern="^(approved|rejected)$")
    reason: str = Field(min_length=1, max_length=512)


class ToolControlInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=512)


class ToolEmergencyInput(ToolControlInput):
    active: bool


class ToolTraceItem(BaseModel):
    id: UUID
    tool_name: str
    tool_version: str
    status: str
    reason: str | None
    target: str
    policy_outcome: str | None
    approval_outcome: str | None
    attempt_outcomes: list[str]
    verification_outcome: str | None
    evidence_ids: list[UUID]
    created_at: datetime
    updated_at: datetime


class ToolTraceView(BaseModel):
    run_id: UUID
    calls: list[ToolTraceItem]


class ToolMutationView(BaseModel):
    call_id: UUID | None = None
    status: str
    revision: int
