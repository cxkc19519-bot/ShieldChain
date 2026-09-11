"""Public, read-only collaboration trajectory schemas."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class StrictView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BudgetView(StrictView):
    step_limit: int
    steps_used: int
    loop_limit: int
    loops_used: int
    time_limit_seconds: int
    time_used_seconds: int
    token_limit: int
    tokens_used: int
    cost_limit_usd: float
    cost_used_usd: float
    tool_call_limit: int
    tool_calls_used: int


class TrajectoryReferenceView(StrictView):
    id: UUID
    kind: Literal["evidence", "knowledge"]
    source_id: str
    observed_at: datetime
    integrity_sha256: str


class RoleStatusView(StrictView):
    role: str
    status: str
    summary: str | None
    reason_code: str | None
    citations: list[TrajectoryReferenceView]
    updated_at: datetime | None


class HandoffView(StrictView):
    id: UUID
    sender: str
    receiver: str
    conclusion: str
    confidence: float
    open_questions: list[str]
    recommended_actions: list[str]
    citations: list[TrajectoryReferenceView]
    created_at: datetime


class CollaborationTrajectoryView(StrictView):
    run_id: UUID
    case_id: UUID
    phase: str
    revision: int
    shared_summary: str
    confirmed_facts: list[str]
    role_statuses: list[RoleStatusView]
    handoffs: list[HandoffView]
    citations: list[TrajectoryReferenceView]
    budget: BudgetView
    reason_codes: list[str]
    updated_at: datetime
