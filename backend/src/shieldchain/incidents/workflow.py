from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Protocol
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.model_planning import AutonomousPlan
from shieldchain.agents.runtime import InvestigationAgentRuntime
from shieldchain.incidents.domain import (
    Assessment,
    BlockOutcome,
    Conclusion,
    Evidence,
    InvestigationRun,
    InvestigationStatus,
    PhishingScenarioState,
    StepStatus,
    ToolCallStatus,
    VerificationResult,
    is_terminal,
)
from shieldchain.incidents.ports import (
    IncidentRepository,
    InvalidInvestigationState,
    InvestigationNotFound,
    SimulationNotFound,
)
from shieldchain.incidents.rules import assess
from shieldchain.incidents.scenario import collect_evidence
from shieldchain.incidents.tools import verify_block

Clock = Callable[[], datetime]
Sleeper = Callable[[float], None]
EvidenceCollector = Callable[[PhishingScenarioState, datetime], tuple[Evidence, ...]]
Assessor = Callable[[tuple[Evidence, ...]], Assessment]
Verifier = Callable[[PhishingScenarioState, IPv4Address, datetime], VerificationResult]


class Firewall(Protocol):
    def block_ip(
        self,
        state: PhishingScenarioState,
        ip: IPv4Address,
        idempotency_key: str,
        *,
        fail_once: bool = False,
    ) -> BlockOutcome: ...


class InvestigationWorkflow:
    def __init__(
        self,
        repository: IncidentRepository,
        firewall: Firewall,
        clock: Clock,
        sleeper: Sleeper,
        step_delay_seconds: float,
        *,
        evidence_collector: EvidenceCollector = collect_evidence,
        assessor: Assessor = assess,
        verifier: Verifier = verify_block,
        agent_runtime: InvestigationAgentRuntime | None = None,
    ) -> None:
        if not 0.0 <= step_delay_seconds <= 2.0:
            raise ValueError("step_delay_seconds must be between 0.0 and 2.0")
        self._repository = repository
        self._firewall = firewall
        self._clock = clock
        self._sleeper = sleeper
        self._step_delay_seconds = step_delay_seconds
        self._evidence_collector = evidence_collector
        self._assessor = assessor
        self._verifier = verifier
        self._agent_runtime = agent_runtime

    def run(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
        fail_block_once: bool = False,
    ) -> InvestigationStatus:
        run = self._load_run(session_factory, run_id)
        if is_terminal(run.status):
            return run.status
        if run.status is not InvestigationStatus.PENDING:
            raise InvalidInvestigationState(run_id, run.status)

        try:
            self._collect(session_factory, run_id, request_id=request_id)
            self._pause()
            assessment = self._analyze(session_factory, run_id, request_id=request_id)
            evidence = self._load_evidence_for_agents(session_factory, run_id)
            plan = self._run_agents(
                run_id,
                evidence=evidence,
                assessment=assessment,
                request_id=request_id,
            )
            if assessment.conclusion is Conclusion.INSUFFICIENT_EVIDENCE:
                return InvestigationStatus.NEEDS_REVIEW
            if plan is not None and not plan.allow_execution:
                return self._hold_for_model_review(
                    session_factory,
                    run_id,
                    request_id=request_id,
                    plan=plan,
                )
            self._pause()
            execution = self._execute(
                session_factory,
                run_id,
                request_id=request_id,
                fail_block_once=fail_block_once,
            )
            if execution is InvestigationStatus.FAILED:
                return execution
            self._pause()
            return self._verify(session_factory, run_id, request_id=request_id)
        except InvalidInvestigationState as error:
            return self._resolve_invalid_state(session_factory, run_id, error)
        except Exception as error:
            return self._record_unexpected_failure(
                session_factory,
                run_id,
                request_id=request_id,
                original_error=error,
            )

    def _load_evidence_for_agents(
        self, session_factory: sessionmaker[Session], run_id: UUID
    ) -> tuple[Evidence, ...]:
        with session_factory() as session:
            return self._load_evidence(session, run_id)

    def _run_agents(
        self,
        run_id: UUID,
        *,
        evidence: tuple[Evidence, ...],
        assessment: Assessment,
        request_id: str,
    ) -> AutonomousPlan | None:
        if self._agent_runtime is None:
            return None
        try:
            return self._agent_runtime.run(
                run_id,
                evidence=evidence,
                assessment=assessment,
                request_id=request_id,
                now=self._clock(),
            )
        except Exception:
            # Model and agent failures fail closed only when a valid plan exists;
            # otherwise the deterministic policy remains the authority.
            return None

    def _hold_for_model_review(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
        plan: AutonomousPlan,
    ) -> InvestigationStatus:
        with session_factory.begin() as session:
            self._require_status(session, run_id, InvestigationStatus.ACTION_PLANNED)
            now = self._clock()
            self._repository.record_step(
                session,
                run_id,
                step_key="model_plan",
                status=StepStatus.SUCCEEDED,
                detail={"decision": "manual_review", "model": plan.model, "summary": plan.summary},
                error_code=None,
                started_at=now,
                completed_at=now,
            )
            self._repository.transition_run(
                session,
                run_id,
                InvestigationStatus.NEEDS_REVIEW,
                request_id=request_id,
                now=now,
            )
        return InvestigationStatus.NEEDS_REVIEW

    def _load_run(self, session_factory: sessionmaker[Session], run_id: UUID) -> InvestigationRun:
        with session_factory() as session:
            run = self._repository.get_run(session, run_id)
        if run is None:
            raise InvestigationNotFound(run_id)
        return run

    def _collect(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
    ) -> tuple[Evidence, ...]:
        with session_factory.begin() as session:
            self._require_status(session, run_id, InvestigationStatus.PENDING)
            started_at = self._clock()
            self._repository.transition_run(
                session,
                run_id,
                InvestigationStatus.COLLECTING,
                request_id=request_id,
                now=started_at,
            )
            self._repository.record_step(
                session,
                run_id,
                step_key="collect",
                status=StepStatus.RUNNING,
                detail={"evidence_count": 0, "evidence_types": []},
                error_code=None,
                started_at=started_at,
                completed_at=None,
            )

        with session_factory.begin() as session:
            run = self._require_status(session, run_id, InvestigationStatus.COLLECTING)
            completed_at = self._clock()
            state = self._require_simulation(session, run.simulation_instance_id)
            evidence = self._evidence_collector(state, completed_at)
            self._repository.append_evidence(session, run_id, evidence, request_id=request_id)
            self._repository.record_step(
                session,
                run_id,
                step_key="collect",
                status=StepStatus.SUCCEEDED,
                detail={
                    "evidence_count": len(evidence),
                    "evidence_types": [item.evidence_type for item in evidence],
                },
                error_code=None,
                started_at=started_at,
                completed_at=completed_at,
            )
            self._repository.transition_run(
                session,
                run_id,
                InvestigationStatus.ANALYZING,
                request_id=request_id,
                now=completed_at,
            )
        return evidence

    def _analyze(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
    ) -> Assessment:
        with session_factory.begin() as session:
            self._require_status(session, run_id, InvestigationStatus.ANALYZING)
            started_at = self._clock()
            self._repository.record_step(
                session,
                run_id,
                step_key="analyze",
                status=StepStatus.RUNNING,
                detail={"conclusion": None, "risk_level": None, "rule_ids": []},
                error_code=None,
                started_at=started_at,
                completed_at=None,
            )

        with session_factory.begin() as session:
            self._require_status(session, run_id, InvestigationStatus.ANALYZING)
            completed_at = self._clock()
            evidence = self._load_evidence(session, run_id)
            assessment = self._assessor(evidence)
            self._repository.save_assessment(
                session,
                run_id,
                assessment,
                request_id=request_id,
                now=completed_at,
            )
            self._repository.record_step(
                session,
                run_id,
                step_key="analyze",
                status=StepStatus.SUCCEEDED,
                detail={
                    "conclusion": assessment.conclusion.value,
                    "risk_level": assessment.risk_level.value,
                    "rule_ids": list(assessment.rule_ids),
                },
                error_code=None,
                started_at=started_at,
                completed_at=completed_at,
            )
            target = (
                InvestigationStatus.NEEDS_REVIEW
                if assessment.conclusion is Conclusion.INSUFFICIENT_EVIDENCE
                else InvestigationStatus.ACTION_PLANNED
            )
            self._repository.transition_run(
                session,
                run_id,
                target,
                request_id=request_id,
                now=completed_at,
            )
        return assessment

    def _execute(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
        fail_block_once: bool,
    ) -> InvestigationStatus:
        with session_factory.begin() as session:
            self._require_status(session, run_id, InvestigationStatus.ACTION_PLANNED)
            started_at = self._clock()
            self._repository.transition_run(
                session,
                run_id,
                InvestigationStatus.EXECUTING,
                request_id=request_id,
                now=started_at,
            )
            self._repository.record_step(
                session,
                run_id,
                step_key="block_ip",
                status=StepStatus.RUNNING,
                detail={"tool_name": "block_ip", "target": None, "result_status": None},
                error_code=None,
                started_at=started_at,
                completed_at=None,
            )

        with session_factory.begin() as session:
            run = self._require_status(session, run_id, InvestigationStatus.EXECUTING)
            completed_at = self._clock()
            state = self._require_simulation(session, run.simulation_instance_id)
            idempotency_key = f"block-ip:{run_id}:{state.remote_ip}"
            outcome = self._firewall.block_ip(
                state,
                state.remote_ip,
                idempotency_key,
                fail_once=fail_block_once,
            )
            result = self._repository.apply_tool_outcome(
                session,
                run_id,
                outcome,
                request_id=request_id,
                now=completed_at,
            )
            failed = result.status is ToolCallStatus.FAILED
            self._repository.record_step(
                session,
                run_id,
                step_key="block_ip",
                status=StepStatus.FAILED if failed else StepStatus.SUCCEEDED,
                detail=(
                    {"error_code": result.error_code}
                    if failed
                    else {
                        "tool_name": result.tool_name,
                        "target": result.target,
                        "result_status": result.status.value,
                    }
                ),
                error_code=result.error_code if failed else None,
                started_at=started_at,
                completed_at=completed_at,
            )
            target = InvestigationStatus.FAILED if failed else InvestigationStatus.VERIFYING
            self._repository.transition_run(
                session,
                run_id,
                target,
                request_id=request_id,
                now=completed_at,
            )
        return target

    def _verify(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
    ) -> InvestigationStatus:
        with session_factory.begin() as session:
            self._require_status(session, run_id, InvestigationStatus.VERIFYING)
            started_at = self._clock()
            self._repository.record_step(
                session,
                run_id,
                step_key="verify",
                status=StepStatus.RUNNING,
                detail={"blocked": False, "connection_stopped": False},
                error_code=None,
                started_at=started_at,
                completed_at=None,
            )

        with session_factory.begin() as session:
            run = self._require_status(session, run_id, InvestigationStatus.VERIFYING)
            completed_at = self._clock()
            state = self._require_simulation(session, run.simulation_instance_id)
            result = self._verifier(state, state.remote_ip, completed_at)
            self._repository.save_verification(session, run_id, result, request_id=request_id)
            succeeded = result.blocked and result.connection_stopped
            error_code = None if succeeded else "verification_failed"
            self._repository.record_step(
                session,
                run_id,
                step_key="verify",
                status=StepStatus.SUCCEEDED if succeeded else StepStatus.FAILED,
                detail=(
                    {
                        "blocked": result.blocked,
                        "connection_stopped": result.connection_stopped,
                    }
                    if succeeded
                    else {"error_code": error_code}
                ),
                error_code=error_code,
                started_at=started_at,
                completed_at=completed_at,
            )
            target = InvestigationStatus.CLOSED if succeeded else InvestigationStatus.FAILED
            self._repository.transition_run(
                session,
                run_id,
                target,
                request_id=request_id,
                now=completed_at,
            )
        return target

    def _record_unexpected_failure(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        *,
        request_id: str,
        original_error: Exception,
    ) -> InvestigationStatus:
        with session_factory.begin() as session:
            run = self._require_run(session, run_id)
            if is_terminal(run.status):
                return run.status
            step_keys = {
                InvestigationStatus.COLLECTING: "collect",
                InvestigationStatus.ANALYZING: "analyze",
                InvestigationStatus.ACTION_PLANNED: "block_ip",
                InvestigationStatus.EXECUTING: "block_ip",
                InvestigationStatus.VERIFYING: "verify",
            }
            step_key = step_keys.get(run.status)
            if step_key is None:
                raise original_error
            now = self._clock()
            target = (
                InvestigationStatus.FAILED
                if run.status
                in {
                    InvestigationStatus.EXECUTING,
                    InvestigationStatus.VERIFYING,
                }
                else InvestigationStatus.INTERRUPTED
            )
            self._repository.record_step(
                session,
                run_id,
                step_key=step_key,
                status=StepStatus.FAILED,
                detail={"error_code": "workflow_step_failed"},
                error_code="workflow_step_failed",
                started_at=now,
                completed_at=now,
            )
            self._repository.transition_run(
                session,
                run_id,
                target,
                request_id=request_id,
                now=now,
            )
        return target

    def _resolve_invalid_state(
        self,
        session_factory: sessionmaker[Session],
        run_id: UUID,
        original_error: InvalidInvestigationState,
    ) -> InvestigationStatus:
        run = self._load_run(session_factory, run_id)
        if is_terminal(run.status):
            return run.status
        raise original_error

    def _require_run(self, session: Session, run_id: UUID) -> InvestigationRun:
        run = self._repository.get_run(session, run_id)
        if run is None:
            raise InvestigationNotFound(run_id)
        return run

    def _require_status(
        self,
        session: Session,
        run_id: UUID,
        expected: InvestigationStatus,
    ) -> InvestigationRun:
        run = self._require_run(session, run_id)
        if run.status is not expected:
            raise InvalidInvestigationState(run_id, run.status)
        return run

    def _require_simulation(self, session: Session, simulation_id: UUID) -> PhishingScenarioState:
        state = self._repository.get_simulation(session, simulation_id)
        if state is None:
            raise SimulationNotFound(simulation_id)
        return state

    @staticmethod
    def _load_evidence(session: Session, run_id: UUID) -> tuple[Evidence, ...]:
        from shieldchain.incidents.persistence import EvidenceRecordRow

        rows = session.query(EvidenceRecordRow).filter_by(run_id=str(run_id)).all()
        return tuple(
            Evidence(
                id=UUID(row.id),
                evidence_type=row.evidence_type,
                source=row.source,
                observed_at=(
                    row.observed_at.replace(tzinfo=UTC)
                    if row.observed_at.tzinfo is None
                    else row.observed_at.astimezone(UTC)
                ),
                summary=row.summary,
                raw_reference=row.raw_reference,
                integrity_sha256=row.integrity_sha256,
                confidence=row.confidence,
                confirmed=row.confirmed,
                payload=row.payload_json,
            )
            for row in rows
        )

    def _pause(self) -> None:
        self._sleeper(self._step_delay_seconds)
