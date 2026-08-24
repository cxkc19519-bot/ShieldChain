"""Immutable public-safe contracts for bounded ReAct loops."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from shieldchain.agents.domain import (
    BudgetSnapshot,
    EvidenceReference,
    KnowledgeReference,
    Reference,
)

_CODE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_ACTION = re.compile(
    r"^proposed:(query_firewall_state|block_ip|query_endpoint_state|isolate_endpoint|"
    r"query_account_state|disable_account)$"
)
_MAX_ITEMS = 100
_MAX_TEXT = 512


class ReactLoopStatus(StrEnum):
    RUNNING = "running"
    AWAITING_EXECUTION = "awaiting_execution"
    AWAITING_HUMAN = "awaiting_human"
    COMPLETED = "completed"
    TERMINATED = "terminated"


class ObservationSource(StrEnum):
    ROLE = "role"
    TOOL_CALL = "tool_call"
    TOOL_VERIFICATION = "tool_verification"
    CONTROL = "control"
    EVIDENCE = "evidence"


class FailureCategory(StrEnum):
    PLAN_ACCEPTED = "plan_accepted"
    COMPLETED = "completed"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_INCONCLUSIVE = "verification_inconclusive"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_OUTCOME_UNKNOWN = "execution_outcome_unknown"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    EMERGENCY_STOPPED = "emergency_stopped"
    AUTOMATION_DISABLED = "automation_disabled"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    EVIDENCE_CONFLICT = "evidence_conflict"
    BUDGET_EXHAUSTED = "budget_exhausted"
    LOOP_DETECTED = "loop_detected"
    UNCLASSIFIED_FAILURE = "unclassified_failure"


class ReactDecision(StrEnum):
    CONTINUE_VERIFICATION = "continue_verification"
    QUERY_STATUS = "query_status"
    RETRY_READ_ONLY = "retry_read_only"
    REPLAN = "replan"
    MANUAL_REVIEW = "manual_review"
    COMPLETE = "complete"


def _uuid(value: UUID, name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")


def _utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")


def _code(value: str, name: str) -> None:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a stable reason code")


def _text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise ValueError(f"{name} is invalid")


def _tuple(values: Iterable[object], name: str) -> tuple[object, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be an iterable")
    try:
        frozen = tuple(values)
    except TypeError as error:
        raise TypeError(f"{name} must be an iterable") from error
    if len(frozen) > _MAX_ITEMS:
        raise ValueError(f"{name} contains too many items")
    return frozen


def _references(values: Iterable[Reference], case_id: UUID) -> tuple[Reference, ...]:
    frozen = _tuple(values, "references")
    if not all(isinstance(item, (EvidenceReference, KnowledgeReference)) for item in frozen):
        raise TypeError("references must contain trusted references")
    if any(item.case_id != case_id for item in frozen):
        raise ValueError("references must belong to the same case")
    return frozen  # type: ignore[return-value]


def _mapping(values: Mapping[str, object], name: str) -> Mapping[str, object]:
    if not isinstance(values, Mapping):
        raise TypeError(f"{name} must be a mapping")
    frozen: dict[str, object] = {}
    for key, value in values.items():
        _code(key, f"{name} key")
        if not isinstance(value, (str, int, float, bool)) or (
            isinstance(value, float) and not math.isfinite(value)
        ):
            raise TypeError(f"{name} values must be JSON scalar values")
        if isinstance(value, str):
            _text(value, f"{name} value")
        frozen[key] = value
    return MappingProxyType(frozen)


@dataclass(frozen=True, slots=True)
class ReactObservation:
    id: UUID
    loop_id: UUID
    case_id: UUID
    run_id: UUID
    iteration: int
    source: ObservationSource
    status: str
    reason_code: str
    references: Iterable[Reference]
    observed_at: datetime
    tool_call_id: UUID | None = None
    verification_id: UUID | None = None

    def __post_init__(self) -> None:
        for name in ("id", "loop_id", "case_id", "run_id"):
            _uuid(getattr(self, name), name)
        if (
            not isinstance(self.iteration, int)
            or isinstance(self.iteration, bool)
            or self.iteration < 0
        ):
            raise ValueError("iteration must be a non-negative integer")
        if not isinstance(self.source, ObservationSource):
            raise TypeError("source must be an ObservationSource")
        _code(self.status, "status")
        _code(self.reason_code, "reason_code")
        object.__setattr__(self, "references", _references(self.references, self.case_id))
        _utc(self.observed_at, "observed_at")
        for name in ("tool_call_id", "verification_id"):
            value = getattr(self, name)
            if value is not None:
                _uuid(value, name)
        if (
            self.source in {ObservationSource.TOOL_CALL, ObservationSource.TOOL_VERIFICATION}
            and self.tool_call_id is None
        ):
            raise ValueError("tool observations must bind a tool_call_id")
        if self.source is ObservationSource.TOOL_VERIFICATION and self.verification_id is None:
            raise ValueError("verification observations must bind a verification_id")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "loop_id": str(self.loop_id),
            "case_id": str(self.case_id),
            "run_id": str(self.run_id),
            "iteration": self.iteration,
            "source": self.source.value,
            "status": self.status,
            "reason_code": self.reason_code,
            "references": [item.to_dict() for item in self.references],
            "observed_at": self.observed_at.isoformat(),
            "tool_call_id": str(self.tool_call_id) if self.tool_call_id else None,
            "verification_id": str(self.verification_id) if self.verification_id else None,
        }


@dataclass(frozen=True, slots=True)
class FailureAssessment:
    id: UUID
    observation_id: UUID
    category: FailureCategory
    recoverable: bool
    confidence: float
    reason_code: str
    assessed_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _uuid(self.observation_id, "observation_id")
        if not isinstance(self.category, FailureCategory):
            raise TypeError("category must be a FailureCategory")
        if not isinstance(self.recoverable, bool):
            raise TypeError("recoverable must be a bool")
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not math.isfinite(self.confidence)
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("confidence must be between 0 and 1")
        _code(self.reason_code, "reason_code")
        _utc(self.assessed_at, "assessed_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "observation_id": str(self.observation_id),
            "category": self.category.value,
            "recoverable": self.recoverable,
            "confidence": self.confidence,
            "reason_code": self.reason_code,
            "assessed_at": self.assessed_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ProposedAction:
    id: UUID
    action: str
    target: str
    expected_state: Mapping[str, object]
    references: Iterable[Reference]

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        if not isinstance(self.action, str) or _ACTION.fullmatch(self.action) is None:
            raise ValueError("action is not an allowed proposed action")
        _text(self.target, "target")
        object.__setattr__(self, "expected_state", _mapping(self.expected_state, "expected_state"))
        references = _tuple(self.references, "references")
        if not references:
            raise ValueError("a proposed action must include a reference")
        if not all(
            isinstance(item, (EvidenceReference, KnowledgeReference)) for item in references
        ):
            raise TypeError("references must contain trusted references")
        case_ids = {item.case_id for item in references}
        if len(case_ids) != 1:
            raise ValueError("action references must belong to one case")
        object.__setattr__(self, "references", references)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "action": self.action,
            "target": self.target,
            "expected_state": dict(self.expected_state),
            "references": [item.to_dict() for item in self.references],
        }


@dataclass(frozen=True, slots=True)
class PlanRevision:
    id: UUID
    loop_id: UUID
    case_id: UUID
    run_id: UUID
    revision: int
    parent_revision: int | None
    retained_action_ids: Iterable[UUID]
    removed_action_ids: Iterable[UUID]
    added_actions: Iterable[ProposedAction]
    reason: FailureCategory
    created_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "loop_id", "case_id", "run_id"):
            _uuid(getattr(self, name), name)
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
        ):
            raise ValueError("revision must be a non-negative integer")
        expected_parent = None if self.revision == 0 else self.revision - 1
        if self.parent_revision != expected_parent:
            raise ValueError("parent_revision must identify the previous revision")
        retained = _tuple(self.retained_action_ids, "retained_action_ids")
        removed = _tuple(self.removed_action_ids, "removed_action_ids")
        added = _tuple(self.added_actions, "added_actions")
        if not all(isinstance(value, UUID) for value in (*retained, *removed)):
            raise TypeError("action identifiers must be UUID values")
        if set(retained) & set(removed):
            raise ValueError("retained and removed actions must be disjoint")
        if not all(isinstance(value, ProposedAction) for value in added):
            raise TypeError("added_actions must contain ProposedAction values")
        for action in added:
            if any(reference.case_id != self.case_id for reference in action.references):
                raise ValueError("added action references must belong to the same case")
        object.__setattr__(self, "retained_action_ids", retained)
        object.__setattr__(self, "removed_action_ids", removed)
        object.__setattr__(self, "added_actions", added)
        if not isinstance(self.reason, FailureCategory):
            raise TypeError("reason must be a FailureCategory")
        _utc(self.created_at, "created_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "loop_id": str(self.loop_id),
            "case_id": str(self.case_id),
            "run_id": str(self.run_id),
            "revision": self.revision,
            "parent_revision": self.parent_revision,
            "retained_action_ids": [str(item) for item in self.retained_action_ids],
            "removed_action_ids": [str(item) for item in self.removed_action_ids],
            "added_actions": [item.to_dict() for item in self.added_actions],
            "reason": self.reason.value,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ReactLoop:
    id: UUID
    case_id: UUID
    run_id: UUID
    status: ReactLoopStatus
    revision: int
    budget: BudgetSnapshot
    observation_fingerprints: Iterable[str]
    started_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "case_id", "run_id"):
            _uuid(getattr(self, name), name)
        if not isinstance(self.status, ReactLoopStatus):
            raise TypeError("status must be a ReactLoopStatus")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
        ):
            raise ValueError("revision must be a non-negative integer")
        if not isinstance(self.budget, BudgetSnapshot):
            raise TypeError("budget must be a BudgetSnapshot")
        fingerprints = _tuple(self.observation_fingerprints, "observation_fingerprints")
        if not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in fingerprints
        ):
            raise ValueError("observation fingerprints must be lowercase SHA-256 values")
        object.__setattr__(self, "observation_fingerprints", fingerprints)
        _utc(self.started_at, "started_at")
        _utc(self.updated_at, "updated_at")
        if self.updated_at < self.started_at:
            raise ValueError("updated_at cannot predate started_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "run_id": str(self.run_id),
            "status": self.status.value,
            "revision": self.revision,
            "budget": self.budget.to_dict(),
            "observation_fingerprints": list(self.observation_fingerprints),
            "started_at": self.started_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ReactStepDecision:
    id: UUID
    loop_id: UUID
    observation_id: UUID
    assessment_id: UUID
    decision: ReactDecision
    reason_code: str
    budget: BudgetSnapshot
    decided_at: datetime
    plan_revision_id: UUID | None = None

    def __post_init__(self) -> None:
        for name in ("id", "loop_id", "observation_id", "assessment_id"):
            _uuid(getattr(self, name), name)
        if not isinstance(self.decision, ReactDecision):
            raise TypeError("decision must be a ReactDecision")
        _code(self.reason_code, "reason_code")
        if not isinstance(self.budget, BudgetSnapshot):
            raise TypeError("budget must be a BudgetSnapshot")
        _utc(self.decided_at, "decided_at")
        if self.plan_revision_id is not None:
            _uuid(self.plan_revision_id, "plan_revision_id")
        if (self.decision is ReactDecision.REPLAN) != (self.plan_revision_id is not None):
            raise ValueError("replan decisions must bind exactly one plan revision")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "loop_id": str(self.loop_id),
            "observation_id": str(self.observation_id),
            "assessment_id": str(self.assessment_id),
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "budget": self.budget.to_dict(),
            "decided_at": self.decided_at.isoformat(),
            "plan_revision_id": str(self.plan_revision_id) if self.plan_revision_id else None,
        }
