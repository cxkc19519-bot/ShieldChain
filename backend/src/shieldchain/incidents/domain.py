import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address
from types import MappingProxyType
from typing import Any, Literal
from uuid import UUID

EvidenceScalar = str | int | float | bool | None


class InvestigationStatus(StrEnum):
    PENDING = "pending"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    ACTION_PLANNED = "action_planned"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    CLOSED = "closed"


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class Conclusion(StrEnum):
    CONFIRMED_THREAT = "confirmed_threat"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class RiskLevel(StrEnum):
    HIGH = "high"
    UNKNOWN = "unknown"


class ToolCallStatus(StrEnum):
    BLOCKED = "blocked"
    ALREADY_BLOCKED = "already_blocked"
    FAILED = "failed"


class RunMode(StrEnum):
    NORMAL = "normal"
    FAIL_BLOCK_ONCE = "fail_block_once"


ACTIVE_INVESTIGATION_STATUSES = (
    InvestigationStatus.PENDING,
    InvestigationStatus.COLLECTING,
    InvestigationStatus.ANALYZING,
    InvestigationStatus.ACTION_PLANNED,
    InvestigationStatus.EXECUTING,
    InvestigationStatus.VERIFYING,
)


ALLOWED_TRANSITIONS: Mapping[InvestigationStatus, frozenset[InvestigationStatus]] = (
    MappingProxyType(
        {
            InvestigationStatus.PENDING: frozenset(
                {InvestigationStatus.COLLECTING, InvestigationStatus.INTERRUPTED}
            ),
            InvestigationStatus.COLLECTING: frozenset(
                {
                    InvestigationStatus.ANALYZING,
                    InvestigationStatus.NEEDS_REVIEW,
                    InvestigationStatus.INTERRUPTED,
                }
            ),
            InvestigationStatus.ANALYZING: frozenset(
                {
                    InvestigationStatus.ACTION_PLANNED,
                    InvestigationStatus.NEEDS_REVIEW,
                    InvestigationStatus.INTERRUPTED,
                }
            ),
            InvestigationStatus.ACTION_PLANNED: frozenset(
                {
                    InvestigationStatus.EXECUTING,
                    InvestigationStatus.NEEDS_REVIEW,
                    InvestigationStatus.INTERRUPTED,
                }
            ),
            InvestigationStatus.EXECUTING: frozenset(
                {
                    InvestigationStatus.VERIFYING,
                    InvestigationStatus.FAILED,
                    InvestigationStatus.INTERRUPTED,
                }
            ),
            InvestigationStatus.VERIFYING: frozenset(
                {
                    InvestigationStatus.CLOSED,
                    InvestigationStatus.FAILED,
                    InvestigationStatus.INTERRUPTED,
                }
            ),
        }
    )
)

_TERMINAL_STATUSES = frozenset(
    {
        InvestigationStatus.NEEDS_REVIEW,
        InvestigationStatus.FAILED,
        InvestigationStatus.INTERRUPTED,
        InvestigationStatus.CLOSED,
    }
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class InvalidInvestigationTransition(ValueError):
    def __init__(self, current: InvestigationStatus, target: InvestigationStatus) -> None:
        self.current = current
        self.target = target
        super().__init__(f"invalid investigation transition: {current.value} -> {target.value}")


def transition(current: InvestigationStatus, target: InvestigationStatus) -> InvestigationStatus:
    if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise InvalidInvestigationTransition(current, target)
    return target


def is_terminal(status: InvestigationStatus) -> bool:
    return status in _TERMINAL_STATUSES


def is_active(status: InvestigationStatus) -> bool:
    return status in ACTIVE_INVESTIGATION_STATUSES


def _require_aware_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be an aware UTC datetime")


def _require_non_empty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_uuid(value: UUID, field_name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{field_name} must be a UUID")


def _require_uuid_tuple(values: tuple[UUID, ...], field_name: str) -> None:
    for value in values:
        _require_uuid(value, field_name)


def _require_port(value: int) -> None:
    if not 1 <= value <= 65535:
        raise ValueError("remote_port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class Evidence:
    id: UUID
    evidence_type: str
    source: str
    observed_at: datetime
    summary: str
    raw_reference: str
    integrity_sha256: str
    confidence: float
    confirmed: bool
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        for field_name in ("evidence_type", "source", "summary", "raw_reference"):
            _require_non_empty(getattr(self, field_name), field_name)
        _require_aware_utc(self.observed_at, "observed_at")
        if _SHA256_PATTERN.fullmatch(self.integrity_sha256) is None:
            raise ValueError("integrity_sha256 must be 64 lowercase hexadecimal characters")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        copied_payload = dict(self.payload)
        for key, value in copied_payload.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("payload keys must not be empty")
            try:
                __import__("json").dumps(value, allow_nan=False)
            except (TypeError, ValueError) as error:
                raise TypeError("payload values must be JSON serializable") from error
        object.__setattr__(self, "payload", MappingProxyType(copied_payload))


@dataclass(frozen=True, slots=True)
class Assessment:
    conclusion: Conclusion
    risk_level: RiskLevel
    rule_ids: tuple[str, ...]
    evidence_ids: tuple[UUID, ...]
    recommended_action: str | None
    explanation: str

    def __post_init__(self) -> None:
        for rule_id in self.rule_ids:
            _require_non_empty(rule_id, "rule_ids")
        _require_uuid_tuple(self.evidence_ids, "evidence_ids")


@dataclass(frozen=True, slots=True)
class ToolResult:
    status: ToolCallStatus
    tool_name: str
    target: str
    idempotency_key: str
    before_state: Mapping[str, str]
    after_state: Mapping[str, str]
    error_code: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty(self.tool_name, "tool_name")
        _require_non_empty(self.target, "target")
        _require_non_empty(self.idempotency_key, "idempotency_key")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    blocked: bool
    connection_stopped: bool
    observed_at: datetime
    evidence_ids: tuple[UUID, ...]

    def __post_init__(self) -> None:
        _require_aware_utc(self.observed_at, "observed_at")
        _require_uuid_tuple(self.evidence_ids, "evidence_ids")


@dataclass(frozen=True, slots=True)
class PhishingScenarioState:
    simulation_id: UUID
    generation: int
    environment: Literal["simulation"]
    incident_id: UUID
    external_incident_id: str
    alert_id: str
    endpoint: str
    username: str
    source_ip: IPv4Address
    alert_status: str
    remote_ip: IPv4Address
    remote_port: int
    process_name: str
    parent_process_name: str
    command_summary: str
    threat_label: str
    connection_status: str
    firewall_status: str
    fail_block_consumed: bool
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.simulation_id, "simulation_id")
        _require_uuid(self.incident_id, "incident_id")
        if self.generation < 1:
            raise ValueError("generation must be at least 1")
        if self.environment != "simulation":
            raise ValueError("environment must be simulation")
        for field_name in (
            "external_incident_id",
            "alert_id",
            "endpoint",
            "username",
            "alert_status",
            "process_name",
            "parent_process_name",
            "command_summary",
            "threat_label",
            "connection_status",
            "firewall_status",
        ):
            _require_non_empty(getattr(self, field_name), field_name)
        _require_port(self.remote_port)
        _require_aware_utc(self.created_at, "created_at")
        _require_aware_utc(self.updated_at, "updated_at")


@dataclass(frozen=True, slots=True)
class BlockOutcome:
    state: PhishingScenarioState
    result: ToolResult


@dataclass(frozen=True, slots=True)
class InvestigationRun:
    id: UUID
    incident_id: UUID
    simulation_instance_id: UUID
    status: InvestigationStatus
    mode: RunMode
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        _require_uuid(self.incident_id, "incident_id")
        _require_uuid(self.simulation_instance_id, "simulation_instance_id")
        _require_aware_utc(self.created_at, "created_at")
        _require_aware_utc(self.updated_at, "updated_at")
        if self.completed_at is not None:
            _require_aware_utc(self.completed_at, "completed_at")


@dataclass(frozen=True, slots=True)
class IncidentDetail:
    id: UUID
    external_id: str
    simulation_instance_id: UUID
    alert_id: str
    endpoint: str
    username: str
    source_ip: IPv4Address
    remote_ip: IPv4Address
    remote_port: int
    process_name: str
    parent_process_name: str
    threat_label: str
    created_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        _require_uuid(self.simulation_instance_id, "simulation_instance_id")
        for field_name in (
            "external_id",
            "alert_id",
            "endpoint",
            "username",
            "process_name",
            "parent_process_name",
            "threat_label",
        ):
            _require_non_empty(getattr(self, field_name), field_name)
        _require_port(self.remote_port)
        _require_aware_utc(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: UUID
    incident_id: UUID
    run_id: UUID | None
    event_type: str
    request_id: str
    occurred_at: datetime
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        _require_uuid(self.incident_id, "incident_id")
        if self.run_id is not None:
            _require_uuid(self.run_id, "run_id")
        _require_non_empty(self.event_type, "event_type")
        _require_non_empty(self.request_id, "request_id")
        _require_aware_utc(self.occurred_at, "occurred_at")
