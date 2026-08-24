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


class ResponsePlanDecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: str = Field(pattern="^(accepted|rejected)$")
    reason: str = Field(min_length=1, max_length=512)


class ResponsePlanControlInput(BaseModel):
    """Optimistic, server-authorized decision for the public plan API."""

    model_config = ConfigDict(extra="forbid")
    current_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=512)


class ResponsePlanToolCallView(BaseModel):
    action_id: UUID
    call_id: UUID
    tool_name: str
    tool_version: str
    status: str
    request_digest: str = Field(pattern="^[0-9a-f]{64}$")


class ResponsePlanMutationView(BaseModel):
    plan_id: UUID
    status: str
    revision: int = Field(ge=0)
    calls: list[ResponsePlanToolCallView]


class ResponsePlanActionView(BaseModel):
    id: UUID
    sequence: int = Field(ge=1, le=8)
    tool_name: str
    tool_version: str
    target_type: str
    target: str
    depends_on: list[UUID]
    evidence_ids: list[UUID]
    public_reason: str
    assessed_risk: str
    approval_required: bool
    verification_tool: str | None
    verification_version: str | None
    rollback_strategy: str
    call_id: UUID | None
    call_status: str | None
    verification_outcome: str | None


class ResponsePlanRevisionView(BaseModel):
    id: UUID
    revision: int = Field(ge=0)
    parent_revision: int | None
    public_summary: str
    reason_code: str | None
    actions: list[ResponsePlanActionView]
    created_at: datetime


class ResponsePlanEventView(BaseModel):
    id: UUID
    revision: int = Field(ge=0)
    event_type: str
    reason_code: str | None
    public_summary: str
    created_at: datetime


class ResponsePlanView(BaseModel):
    plan_id: UUID
    run_id: UUID
    case_id: UUID | None
    status: str
    current_revision: int = Field(ge=0)
    revisions: list[ResponsePlanRevisionView]
    events: list[ResponsePlanEventView]
    created_at: datetime
    updated_at: datetime


class ToolTraceItem(BaseModel):
    id: UUID
    plan_id: UUID
    plan_revision_id: UUID | None = None
    plan_action_id: UUID | None = None
    tool_name: str
    tool_version: str
    status: str
    reason: str | None
    target: str
    policy_outcome: str | None
    risk: str | None
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
