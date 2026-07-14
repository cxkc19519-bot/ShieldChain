from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from sqlalchemy.orm import Session

from shieldchain.incidents.domain import (
    Assessment,
    AuditEvent,
    BlockOutcome,
    Evidence,
    IncidentDetail,
    InvestigationRun,
    InvestigationStatus,
    PhishingScenarioState,
    RunMode,
    StepStatus,
    ToolResult,
    VerificationResult,
)


class SimulationNotFound(RuntimeError):
    def __init__(self, simulation_id: UUID) -> None:
        self.simulation_id = simulation_id
        super().__init__(f"simulation not found: {simulation_id}")


class InvestigationNotFound(RuntimeError):
    def __init__(self, run_id: UUID) -> None:
        self.run_id = run_id
        super().__init__(f"investigation not found: {run_id}")


class InvalidInvestigationState(RuntimeError):
    def __init__(self, run_id: UUID, status: InvestigationStatus) -> None:
        self.run_id = run_id
        self.status = status
        super().__init__(f"invalid investigation state for {run_id}: {status.value}")


class IncidentNotFound(RuntimeError):
    def __init__(self, incident_id: UUID) -> None:
        self.incident_id = incident_id
        super().__init__(f"incident not found: {incident_id}")


class ActiveInvestigationExists(RuntimeError):
    def __init__(self, simulation_id: UUID) -> None:
        self.simulation_id = simulation_id
        super().__init__(f"active investigation exists: {simulation_id}")


class DuplicateEvidence(RuntimeError):
    def __init__(self, evidence_id: UUID) -> None:
        self.evidence_id = evidence_id
        super().__init__(f"duplicate evidence: {evidence_id}")


class DuplicateIdempotencyKey(RuntimeError):
    def __init__(self, idempotency_key: str) -> None:
        self.idempotency_key = idempotency_key
        super().__init__(f"duplicate idempotency key: {idempotency_key}")


class RunSimulationMismatch(RuntimeError):
    def __init__(self, run_id: UUID, simulation_id: UUID) -> None:
        self.run_id = run_id
        self.simulation_id = simulation_id
        super().__init__(f"run simulation mismatch: {run_id} {simulation_id}")


ScenarioFactory = Callable[[datetime], PhishingScenarioState]


@runtime_checkable
class IncidentRepository(Protocol):
    def reset_phishing_scenario(
        self, session: Session, *, now: datetime, request_id: str = "simulation-reset"
    ) -> PhishingScenarioState: ...

    def create_run(
        self,
        session: Session,
        *,
        simulation_id: UUID,
        mode: RunMode,
        request_id: str,
        now: datetime,
    ) -> InvestigationRun: ...

    def cancel_pending_run(self, session: Session, run_id: UUID) -> None: ...

    def get_run(self, session: Session, run_id: UUID) -> InvestigationRun | None: ...

    def get_simulation(
        self, session: Session, simulation_id: UUID
    ) -> PhishingScenarioState | None: ...

    def record_step(
        self,
        session: Session,
        run_id: UUID,
        *,
        step_key: str,
        status: StepStatus,
        detail: Mapping[str, object],
        error_code: str | None,
        started_at: datetime,
        completed_at: datetime | None,
    ) -> None: ...

    def transition_run(
        self,
        session: Session,
        run_id: UUID,
        target: InvestigationStatus,
        *,
        request_id: str,
        now: datetime,
    ) -> InvestigationRun: ...

    def append_evidence(
        self,
        session: Session,
        run_id: UUID,
        evidence: Sequence[Evidence],
        *,
        request_id: str,
    ) -> None: ...

    def save_assessment(
        self,
        session: Session,
        run_id: UUID,
        assessment: Assessment,
        *,
        request_id: str,
        now: datetime,
    ) -> None: ...

    def get_tool_result(
        self, session: Session, idempotency_key: str
    ) -> ToolResult | None: ...

    def apply_tool_outcome(
        self,
        session: Session,
        run_id: UUID,
        outcome: BlockOutcome,
        *,
        request_id: str,
        now: datetime,
    ) -> ToolResult: ...

    def save_verification(
        self,
        session: Session,
        run_id: UUID,
        result: VerificationResult,
        *,
        request_id: str,
    ) -> None: ...

    def get_incident(
        self, session: Session, incident_id: UUID
    ) -> IncidentDetail | None: ...

    def list_audit(
        self, session: Session, incident_id: UUID
    ) -> Sequence[AuditEvent]: ...

    def mark_recoverable_runs_interrupted(
        self, session: Session, *, request_id: str, now: datetime
    ) -> int: ...
