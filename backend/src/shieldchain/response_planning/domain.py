from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID


class ResponsePlanStatus(StrEnum):
    DRAFT = "draft"
    PROPOSED = "proposed"
    NEEDS_REVIEW = "needs_review"
    REJECTED = "rejected"
    COMPLETED_ADVISORY = "completed_advisory"
    AWAITING_EXECUTION = "awaiting_execution"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    REPLANNING = "replanning"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    LEGACY_IMPORTED = "legacy_imported"


_TRANSITIONS = {
    ResponsePlanStatus.DRAFT: {
        ResponsePlanStatus.PROPOSED,
        ResponsePlanStatus.NEEDS_REVIEW,
        ResponsePlanStatus.COMPLETED_ADVISORY,
    },
    ResponsePlanStatus.PROPOSED: {
        ResponsePlanStatus.REJECTED,
        ResponsePlanStatus.COMPLETED_ADVISORY,
        ResponsePlanStatus.AWAITING_EXECUTION,
        ResponsePlanStatus.NEEDS_REVIEW,
    },
    ResponsePlanStatus.AWAITING_EXECUTION: {
        ResponsePlanStatus.EXECUTING,
        ResponsePlanStatus.CANCELLED,
        ResponsePlanStatus.NEEDS_REVIEW,
    },
    ResponsePlanStatus.EXECUTING: {
        ResponsePlanStatus.VERIFYING,
        ResponsePlanStatus.REPLANNING,
        ResponsePlanStatus.NEEDS_REVIEW,
    },
    ResponsePlanStatus.VERIFYING: {
        ResponsePlanStatus.COMPLETED,
        ResponsePlanStatus.REPLANNING,
        ResponsePlanStatus.NEEDS_REVIEW,
    },
    ResponsePlanStatus.REPLANNING: {
        ResponsePlanStatus.PROPOSED,
        ResponsePlanStatus.NEEDS_REVIEW,
    },
}


@dataclass(frozen=True, slots=True)
class ResponsePlan:
    id: UUID
    tenant_id: UUID
    run_id: UUID
    case_id: UUID | None
    status: ResponsePlanStatus
    current_revision: int
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "tenant_id", "run_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if self.case_id is not None and not isinstance(self.case_id, UUID):
            raise TypeError("case_id must be a UUID or None")
        if not isinstance(self.status, ResponsePlanStatus):
            raise TypeError("status must be a ResponsePlanStatus")
        if not isinstance(self.current_revision, int) or self.current_revision < 0:
            raise ValueError("current_revision must be non-negative")
        _utc(self.created_at)
        _utc(self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")

    def transition(self, target: ResponsePlanStatus, *, now: datetime) -> ResponsePlan:
        _utc(now)
        if target not in _TRANSITIONS.get(self.status, set()):
            raise ValueError(f"invalid response plan transition: {self.status} -> {target}")
        return replace(self, status=target, updated_at=now)


def _utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("response plan datetimes must be aware UTC")
