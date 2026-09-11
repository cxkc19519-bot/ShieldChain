from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar
from uuid import UUID

_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_TEXT = 4096
_MAX_ITEMS = 1000


class AgentRole(StrEnum):
    SUPERAGENT = "superagent"
    ALERT_TRIAGE = "alert_triage"
    THREAT_INVESTIGATION = "threat_investigation"
    KNOWLEDGE_RETRIEVAL = "knowledge_retrieval"
    RESPONSE_PLANNING = "response_planning"
    VERIFICATION = "verification"
    REPORTING = "reporting"


class CasePhase(StrEnum):
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    RETRIEVAL = "retrieval"
    RESPONSE_PLANNING = "response_planning"
    AWAITING_EXECUTION = "awaiting_execution"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    NEEDS_REVIEW = "needs_review"
    CLOSED = "closed"


class ReferenceKind(StrEnum):
    EVIDENCE = "evidence"
    KNOWLEDGE = "knowledge"


class TerminationReason(StrEnum):
    COMPLETED = "completed"
    NEEDS_REVIEW = "needs_review"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNSAFE = "unsafe"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    FAILED = "failed"


def _uuid(value: UUID, name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")


def _text(value: str, name: str, *, maximum: int = _MAX_TEXT) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds maximum length {maximum}")


def _utc(value: datetime, name: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{name} must be an aware UTC datetime")


def _confidence(value: float, name: str = "confidence") -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError(f"{name} must be between 0 and 1")


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


def _strings(values: Iterable[str], name: str) -> tuple[str, ...]:
    frozen = _tuple(values, name)
    for value in frozen:
        _text(value, name)
    return frozen  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class TrustedReference:
    id: UUID
    case_id: UUID
    source_id: str
    observed_at: datetime
    integrity_sha256: str
    kind: ReferenceKind = field(init=False)

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _uuid(self.case_id, "case_id")
        _text(self.source_id, "source_id", maximum=512)
        _utc(self.observed_at, "observed_at")
        if not isinstance(self.integrity_sha256, str) or _SHA256.fullmatch(
            self.integrity_sha256
        ) is None:
            raise ValueError(
                "integrity_sha256 must be 64 lowercase hexadecimal characters"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "source_id": self.source_id,
            "observed_at": self.observed_at.isoformat(),
            "integrity_sha256": self.integrity_sha256,
            "kind": self.kind.value,
        }


@dataclass(frozen=True, slots=True)
class EvidenceReference(TrustedReference):
    kind: ReferenceKind = field(default=ReferenceKind.EVIDENCE, init=False)


@dataclass(frozen=True, slots=True)
class KnowledgeReference(TrustedReference):
    kind: ReferenceKind = field(default=ReferenceKind.KNOWLEDGE, init=False)


Reference = EvidenceReference | KnowledgeReference


def _references(values: Iterable[Reference], name: str = "references") -> tuple[Reference, ...]:
    frozen = _tuple(values, name)
    if not all(isinstance(value, (EvidenceReference, KnowledgeReference)) for value in frozen):
        raise TypeError(f"{name} must contain trusted references")
    return frozen  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class ConfirmedFact:
    id: UUID
    statement: str
    confirmed: bool
    references: Iterable[Reference]
    confidence: float
    confirmed_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _text(self.statement, "statement")
        if self.confirmed is not True:
            raise ValueError("a shared fact must be confirmed")
        references = _references(self.references)
        if not references:
            raise ValueError("a confirmed fact must include a reference")
        object.__setattr__(self, "references", references)
        _confidence(self.confidence)
        _utc(self.confirmed_at, "confirmed_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "statement": self.statement,
            "confirmed": self.confirmed,
            "references": [item.to_dict() for item in self.references],
            "confidence": self.confidence,
            "confirmed_at": self.confirmed_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class Hypothesis:
    id: UUID
    statement: str
    confidence: float
    references: Iterable[Reference]

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _text(self.statement, "statement")
        _confidence(self.confidence)
        object.__setattr__(self, "references", _references(self.references))

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "statement": self.statement,
            "confidence": self.confidence,
            "references": [item.to_dict() for item in self.references],
        }


@dataclass(frozen=True, slots=True)
class Risk:
    id: UUID
    description: str
    severity: str
    references: Iterable[Reference]

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _text(self.description, "description")
        if self.severity not in {"low", "medium", "high", "critical", "unknown"}:
            raise ValueError("severity is not supported")
        object.__setattr__(self, "references", _references(self.references))

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "description": self.description,
            "severity": self.severity,
            "references": [item.to_dict() for item in self.references],
        }


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
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

    _LIMITS: ClassVar[Mapping[str, float]] = MappingProxyType(
        {
            "step_limit": 1000,
            "loop_limit": 100,
            "time_limit_seconds": 86_400,
            "token_limit": 2_000_000,
            "cost_limit_usd": 1000.0,
            "tool_call_limit": 10_000,
        }
    )

    def __post_init__(self) -> None:
        integer_fields = (
            "step_limit",
            "steps_used",
            "loop_limit",
            "loops_used",
            "time_limit_seconds",
            "time_used_seconds",
            "token_limit",
            "tokens_used",
            "tool_call_limit",
            "tool_calls_used",
        )
        if any(
            not isinstance(getattr(self, name), int)
            or isinstance(getattr(self, name), bool)
            for name in integer_fields
        ):
            raise TypeError("count and duration budget values must be integers")
        pairs = (
            ("step", self.step_limit, self.steps_used),
            ("loop", self.loop_limit, self.loops_used),
            ("time", self.time_limit_seconds, self.time_used_seconds),
            ("token", self.token_limit, self.tokens_used),
            ("cost", self.cost_limit_usd, self.cost_used_usd),
            ("tool_call", self.tool_call_limit, self.tool_calls_used),
        )
        for name, limit, used in pairs:
            if (
                not isinstance(limit, (int, float))
                or isinstance(limit, bool)
                or not math.isfinite(limit)
                or not isinstance(used, (int, float))
                or isinstance(used, bool)
                or not math.isfinite(used)
                or limit < 0
                or used < 0
            ):
                raise ValueError(f"{name} budget values must be non-negative")
            if used > limit:
                raise ValueError(f"{name} budget usage cannot exceed its limit")
        for field_name, maximum in self._LIMITS.items():
            if getattr(self, field_name) > maximum:
                raise ValueError(f"{field_name} exceeds its hard maximum")

    def to_dict(self) -> dict[str, int | float]:
        return {
            name: getattr(self, name)
            for name in (
                "step_limit",
                "steps_used",
                "loop_limit",
                "loops_used",
                "time_limit_seconds",
                "time_used_seconds",
                "token_limit",
                "tokens_used",
                "cost_limit_usd",
                "cost_used_usd",
                "tool_call_limit",
                "tool_calls_used",
            )
        }


def _validate_case_references(case_id: UUID, references: Iterable[Reference]) -> None:
    if any(reference.case_id != case_id for reference in references):
        raise ValueError("references must belong to the same case")


@dataclass(frozen=True, slots=True)
class SharedCaseContext:
    case_id: UUID
    phase: CasePhase
    user_goal: str
    confirmed_facts: Iterable[ConfirmedFact]
    hypotheses: Iterable[Hypothesis]
    risks: Iterable[Risk]
    plan: Iterable[str]
    step_status: Mapping[str, str]
    disposition_status: str
    budget: BudgetSnapshot
    revision: int
    updated_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.case_id, "case_id")
        if not isinstance(self.phase, CasePhase):
            raise TypeError("phase must be a CasePhase")
        _text(self.user_goal, "user_goal")
        facts = _tuple(self.confirmed_facts, "confirmed_facts")
        hypotheses = _tuple(self.hypotheses, "hypotheses")
        risks = _tuple(self.risks, "risks")
        if not all(isinstance(item, ConfirmedFact) for item in facts):
            raise TypeError("confirmed_facts must contain ConfirmedFact values")
        if not all(isinstance(item, Hypothesis) for item in hypotheses):
            raise TypeError("hypotheses must contain Hypothesis values")
        if not all(isinstance(item, Risk) for item in risks):
            raise TypeError("risks must contain Risk values")
        for item in (*facts, *hypotheses, *risks):
            _validate_case_references(self.case_id, item.references)
        object.__setattr__(self, "confirmed_facts", facts)
        object.__setattr__(self, "hypotheses", hypotheses)
        object.__setattr__(self, "risks", risks)
        object.__setattr__(self, "plan", _strings(self.plan, "plan"))
        if not isinstance(self.step_status, Mapping):
            raise TypeError("step_status must be a mapping")
        statuses = dict(self.step_status)
        for key, value in statuses.items():
            _text(key, "step_status key", maximum=128)
            _text(value, "step_status value", maximum=128)
        object.__setattr__(self, "step_status", MappingProxyType(statuses))
        _text(self.disposition_status, "disposition_status", maximum=128)
        if not isinstance(self.budget, BudgetSnapshot):
            raise TypeError("budget must be a BudgetSnapshot")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
        ):
            raise ValueError("revision must be a non-negative integer")
        _utc(self.updated_at, "updated_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": str(self.case_id),
            "phase": self.phase.value,
            "user_goal": self.user_goal,
            "confirmed_facts": [item.to_dict() for item in self.confirmed_facts],
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "risks": [item.to_dict() for item in self.risks],
            "plan": list(self.plan),
            "step_status": dict(self.step_status),
            "disposition_status": self.disposition_status,
            "budget": self.budget.to_dict(),
            "revision": self.revision,
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class PrivateContext:
    case_id: UUID
    owner: AgentRole
    working_items: Mapping[str, Iterable[str]]
    references: Iterable[Reference]
    updated_at: datetime

    EXPECTED_OWNER: ClassVar[AgentRole]

    def __post_init__(self) -> None:
        _uuid(self.case_id, "case_id")
        if self.owner is not self.EXPECTED_OWNER:
            raise ValueError(f"owner must be {self.EXPECTED_OWNER.value}")
        if not isinstance(self.working_items, Mapping):
            raise TypeError("working_items must be a mapping")
        items: dict[str, tuple[str, ...]] = {}
        for key, values in self.working_items.items():
            _text(key, "working_items key", maximum=128)
            items[key] = _strings(values, "working_items values")
        object.__setattr__(self, "working_items", MappingProxyType(items))
        references = _references(self.references)
        _validate_case_references(self.case_id, references)
        object.__setattr__(self, "references", references)
        _utc(self.updated_at, "updated_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": str(self.case_id),
            "owner": self.owner.value,
            "working_items": {
                key: list(values) for key, values in self.working_items.items()
            },
            "references": [item.to_dict() for item in self.references],
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class SuperagentPrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.SUPERAGENT


@dataclass(frozen=True, slots=True)
class AlertTriagePrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.ALERT_TRIAGE


@dataclass(frozen=True, slots=True)
class ThreatInvestigationPrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.THREAT_INVESTIGATION


@dataclass(frozen=True, slots=True)
class KnowledgeRetrievalPrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.KNOWLEDGE_RETRIEVAL


@dataclass(frozen=True, slots=True)
class ResponsePlanningPrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.RESPONSE_PLANNING


@dataclass(frozen=True, slots=True)
class VerificationPrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.VERIFICATION


@dataclass(frozen=True, slots=True)
class ReportingPrivateContext(PrivateContext):
    EXPECTED_OWNER: ClassVar[AgentRole] = AgentRole.REPORTING


AgentPrivateContext = (
    SuperagentPrivateContext
    | AlertTriagePrivateContext
    | ThreatInvestigationPrivateContext
    | KnowledgeRetrievalPrivateContext
    | ResponsePlanningPrivateContext
    | VerificationPrivateContext
    | ReportingPrivateContext
)


@dataclass(frozen=True, slots=True)
class HandoffPacket:
    id: UUID
    case_id: UUID
    sender: AgentRole
    receiver: AgentRole
    conclusion: str
    references: Iterable[Reference]
    confidence: float
    open_questions: Iterable[str]
    recommended_actions: Iterable[str]
    created_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _uuid(self.case_id, "case_id")
        if not isinstance(self.sender, AgentRole) or not isinstance(self.receiver, AgentRole):
            raise TypeError("sender and receiver must be AgentRole values")
        if self.sender is self.receiver:
            raise ValueError("sender and receiver must be different")
        _text(self.conclusion, "conclusion")
        references = _references(self.references)
        _validate_case_references(self.case_id, references)
        _confidence(self.confidence)
        if self.confidence >= 0.8 and not references:
            raise ValueError("a high-confidence handoff must include a reference")
        object.__setattr__(self, "references", references)
        object.__setattr__(
            self, "open_questions", _strings(self.open_questions, "open_questions")
        )
        actions = _strings(self.recommended_actions, "recommended_actions")
        if not actions:
            raise ValueError("recommended_actions must not be empty")
        object.__setattr__(self, "recommended_actions", actions)
        _utc(self.created_at, "created_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "sender": self.sender.value,
            "receiver": self.receiver.value,
            "conclusion": self.conclusion,
            "references": [item.to_dict() for item in self.references],
            "confidence": self.confidence,
            "open_questions": list(self.open_questions),
            "recommended_actions": list(self.recommended_actions),
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class AgentOutput:
    role: AgentRole
    case_id: UUID
    summary: str
    references: Iterable[Reference]
    hypotheses: Iterable[Hypothesis]
    risks: Iterable[Risk]
    recommended_actions: Iterable[str]
    created_at: datetime
    termination_reason: TerminationReason = TerminationReason.COMPLETED

    def __post_init__(self) -> None:
        if not isinstance(self.role, AgentRole):
            raise TypeError("role must be an AgentRole")
        _uuid(self.case_id, "case_id")
        _text(self.summary, "summary")
        references = _references(self.references)
        hypotheses = _tuple(self.hypotheses, "hypotheses")
        risks = _tuple(self.risks, "risks")
        if not all(isinstance(item, Hypothesis) for item in hypotheses):
            raise TypeError("hypotheses must contain Hypothesis values")
        if not all(isinstance(item, Risk) for item in risks):
            raise TypeError("risks must contain Risk values")
        for item in (*hypotheses, *risks):
            _validate_case_references(self.case_id, item.references)
        _validate_case_references(self.case_id, references)
        object.__setattr__(self, "references", references)
        object.__setattr__(self, "hypotheses", hypotheses)
        object.__setattr__(self, "risks", risks)
        object.__setattr__(
            self,
            "recommended_actions",
            _strings(self.recommended_actions, "recommended_actions"),
        )
        _utc(self.created_at, "created_at")
        if not isinstance(self.termination_reason, TerminationReason):
            raise TypeError("termination_reason must be a TerminationReason")

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "case_id": str(self.case_id),
            "summary": self.summary,
            "references": [item.to_dict() for item in self.references],
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "risks": [item.to_dict() for item in self.risks],
            "recommended_actions": list(self.recommended_actions),
            "created_at": self.created_at.isoformat(),
            "termination_reason": self.termination_reason.value,
        }
