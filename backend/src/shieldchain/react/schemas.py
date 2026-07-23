"""Strict public projections and mutation inputs for controlled ReAct loops."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from shieldchain.agents.schemas import BudgetView, TrajectoryReferenceView


class StrictReactView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReactControlInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=512)


class ReactObservationView(StrictReactView):
    id: UUID
    iteration: int
    source: str
    status: str
    reason_code: str
    citations: list[TrajectoryReferenceView]
    tool_call_id: UUID | None
    verification_id: UUID | None
    observed_at: datetime


class ReactAssessmentView(StrictReactView):
    id: UUID
    observation_id: UUID
    category: str
    recoverable: bool
    confidence: float
    reason_code: str
    assessed_at: datetime


class ReactActionView(StrictReactView):
    id: UUID
    action: str
    target: str
    expected_state: dict[str, str | int | float | bool]
    citations: list[TrajectoryReferenceView]


class ReactPlanRevisionView(StrictReactView):
    id: UUID
    revision: int
    parent_revision: int | None
    retained_action_ids: list[UUID]
    removed_action_ids: list[UUID]
    added_actions: list[ReactActionView]
    reason: str
    created_at: datetime


class ReactDecisionView(StrictReactView):
    id: UUID
    observation_id: UUID
    assessment_id: UUID
    decision: str
    reason_code: str
    budget: BudgetView
    plan_revision_id: UUID | None
    decided_at: datetime


class ReactControlEventView(StrictReactView):
    id: UUID
    action: Literal["takeover", "resume"]
    from_status: str
    to_status: str
    reason_code: str
    revision: int
    created_at: datetime


class ReactTrajectoryView(StrictReactView):
    loop_id: UUID
    run_id: UUID
    case_id: UUID
    status: str
    revision: int
    budget: BudgetView
    observations: list[ReactObservationView]
    assessments: list[ReactAssessmentView]
    plan_revisions: list[ReactPlanRevisionView]
    decisions: list[ReactDecisionView]
    controls: list[ReactControlEventView]
    updated_at: datetime


class ReactMutationView(StrictReactView):
    loop_id: UUID
    status: str
    revision: int
