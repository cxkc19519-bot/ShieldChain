from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
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
    ToolCallStatus,
    ToolResult,
    VerificationResult,
    is_terminal,
    transition,
)
from shieldchain.incidents.persistence import (
    ACTIVE_VALUES,
    AuditEventRow,
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
    SimulationToolCallRow,
)
from shieldchain.incidents.ports import (
    ActiveInvestigationExists,
    DuplicateEvidence,
    DuplicateIdempotencyKey,
    IncidentNotFound,
    InvestigationNotFound,
    RunSimulationMismatch,
    ScenarioFactory,
    SimulationNotFound,
)

_RECOVERABLE_STATUSES = (
    InvestigationStatus.COLLECTING,
    InvestigationStatus.ANALYZING,
    InvestigationStatus.EXECUTING,
    InvestigationStatus.VERIFYING,
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _run_from_row(row: InvestigationRunRow) -> InvestigationRun:
    return InvestigationRun(
        id=UUID(row.id),
        incident_id=UUID(row.incident_id),
        simulation_instance_id=UUID(row.simulation_instance_id),
        status=InvestigationStatus(row.status),
        mode=RunMode(row.mode),
        created_at=_utc(row.created_at),
        updated_at=_utc(row.updated_at),
        completed_at=_utc(row.completed_at) if row.completed_at is not None else None,
    )


def _incident_from_row(row: IncidentRow) -> IncidentDetail:
    return IncidentDetail(
        id=UUID(row.id),
        external_id=row.external_id,
        simulation_instance_id=UUID(row.simulation_instance_id),
        alert_id=row.alert_id,
        endpoint=row.endpoint,
        username=row.username,
        source_ip=IPv4Address(row.source_ip),
        remote_ip=IPv4Address(row.remote_ip),
        remote_port=row.remote_port,
        process_name=row.process_name,
        parent_process_name=row.parent_process_name,
        threat_label=row.threat_label,
        created_at=_utc(row.created_at),
    )


def _tool_result_from_row(row: SimulationToolCallRow) -> ToolResult:
    return ToolResult(
        status=ToolCallStatus(row.status),
        tool_name=row.tool_name,
        target=row.target,
        idempotency_key=row.idempotency_key,
        before_state=dict(row.before_state_json),
        after_state=dict(row.after_state_json),
        error_code=row.error_code,
    )


class SqlAlchemyIncidentRepository:
    def __init__(self, scenario_factory: ScenarioFactory) -> None:
        self._scenario_factory = scenario_factory

    def reset_phishing_scenario(
        self, session: Session, *, now: datetime
    ) -> PhishingScenarioState:
        active = session.execute(
            select(InvestigationRunRow.simulation_instance_id)
            .join(
                SimulationInstanceRow,
                SimulationInstanceRow.id == InvestigationRunRow.simulation_instance_id,
            )
            .where(
                SimulationInstanceRow.scenario_key == "phishing",
                InvestigationRunRow.status.in_(ACTIVE_VALUES),
            )
            .with_for_update()
            .limit(1)
        ).scalar_one_or_none()
        if active is not None:
            raise ActiveInvestigationExists(UUID(active))

        generation = (
            session.execute(
                select(func.max(SimulationInstanceRow.generation)).where(
                    SimulationInstanceRow.scenario_key == "phishing"
                )
            ).scalar_one()
            or 0
        ) + 1
        state = replace(self._scenario_factory(now), generation=generation)
        simulation = SimulationInstanceRow(
            id=str(state.simulation_id),
            scenario_key="phishing",
            generation=state.generation,
            environment=state.environment,
            connection_status=state.connection_status,
            firewall_status=state.firewall_status,
            fail_block_consumed=state.fail_block_consumed,
            created_at=state.created_at,
            updated_at=state.updated_at,
        )
        incident = IncidentRow(
            id=str(state.incident_id),
            external_id=state.external_incident_id,
            simulation_instance_id=str(state.simulation_id),
            alert_id=state.alert_id,
            alert_status=state.alert_status,
            endpoint=state.endpoint,
            username=state.username,
            source_ip=str(state.source_ip),
            remote_ip=str(state.remote_ip),
            remote_port=state.remote_port,
            process_name=state.process_name,
            parent_process_name=state.parent_process_name,
            command_summary=state.command_summary,
            threat_label=state.threat_label,
            created_at=state.created_at,
        )
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            session.add(simulation)
            session.flush()
            session.add(incident)
            session.flush()
            self._append_audit(
                session,
                incident_id=state.incident_id,
                run_id=None,
                event_type="simulation_reset",
                request_id="simulation-reset",
                occurred_at=now,
                payload={
                    "simulation_id": str(state.simulation_id),
                    "generation": generation,
                },
            )
            session.flush()
        return state

    def create_run(
        self,
        session: Session,
        *,
        simulation_id: UUID,
        mode: RunMode,
        request_id: str,
        now: datetime,
    ) -> InvestigationRun:
        incident_id = session.execute(
            select(IncidentRow.id)
            .where(IncidentRow.simulation_instance_id == str(simulation_id))
            .with_for_update()
        ).scalar_one_or_none()
        if incident_id is None:
            raise SimulationNotFound(simulation_id)
        row = InvestigationRunRow(
            id=str(uuid4()),
            incident_id=incident_id,
            simulation_instance_id=str(simulation_id),
            status=InvestigationStatus.PENDING.value,
            mode=mode.value,
            created_at=now,
            updated_at=now,
        )
        self._ensure_sqlite_outer_transaction(session)
        try:
            with session.begin_nested():
                session.add(row)
                self._append_audit(
                    session,
                    incident_id=UUID(incident_id),
                    run_id=UUID(row.id),
                    event_type="run_created",
                    request_id=request_id,
                    occurred_at=now,
                    payload={"run_id": row.id, "status": InvestigationStatus.PENDING.value},
                )
                session.flush()
        except IntegrityError as error:
            if not self._matches_integrity_error(
                error,
                constraint_name="uq_active_run_per_simulation",
                sqlite_signature="investigation_runs.simulation_instance_id",
            ):
                raise
            raise ActiveInvestigationExists(simulation_id) from None
        return _run_from_row(row)

    def get_run(self, session: Session, run_id: UUID) -> InvestigationRun | None:
        row = session.get(InvestigationRunRow, str(run_id))
        return _run_from_row(row) if row is not None else None

    def get_simulation(
        self, session: Session, simulation_id: UUID
    ) -> PhishingScenarioState | None:
        result = session.execute(
            select(SimulationInstanceRow, IncidentRow)
            .join(
                IncidentRow,
                IncidentRow.simulation_instance_id == SimulationInstanceRow.id,
            )
            .where(SimulationInstanceRow.id == str(simulation_id))
        ).one_or_none()
        if result is None:
            return None
        simulation, incident = result
        return PhishingScenarioState(
            simulation_id=UUID(simulation.id),
            generation=simulation.generation,
            environment="simulation",
            incident_id=UUID(incident.id),
            external_incident_id=incident.external_id,
            alert_id=incident.alert_id,
            endpoint=incident.endpoint,
            username=incident.username,
            source_ip=IPv4Address(incident.source_ip),
            alert_status=incident.alert_status,
            remote_ip=IPv4Address(incident.remote_ip),
            remote_port=incident.remote_port,
            process_name=incident.process_name,
            parent_process_name=incident.parent_process_name,
            command_summary=incident.command_summary,
            threat_label=incident.threat_label,
            connection_status=simulation.connection_status,
            firewall_status=simulation.firewall_status,
            fail_block_consumed=simulation.fail_block_consumed,
            created_at=_utc(simulation.created_at),
            updated_at=_utc(simulation.updated_at),
        )

    def transition_run(
        self,
        session: Session,
        run_id: UUID,
        target: InvestigationStatus,
        *,
        request_id: str,
        now: datetime,
    ) -> InvestigationRun:
        row = self._require_run(session, run_id, lock=True)
        current = InvestigationStatus(row.status)
        transition(current, target)
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            row.status = target.value
            row.updated_at = now
            row.completed_at = now if is_terminal(target) else None
            self._append_audit(
                session,
                incident_id=UUID(row.incident_id),
                run_id=run_id,
                event_type="status_changed",
                request_id=request_id,
                occurred_at=now,
                payload={"from_status": current.value, "to_status": target.value},
            )
            session.flush()
        return _run_from_row(row)

    def append_evidence(
        self,
        session: Session,
        run_id: UUID,
        evidence: Sequence[Evidence],
        *,
        request_id: str,
    ) -> None:
        run = self._require_run(session, run_id)
        if not evidence:
            return
        duplicate = self._find_duplicate_evidence(session, run_id, evidence)
        if duplicate is not None:
            raise DuplicateEvidence(duplicate)
        rows = [
            EvidenceRecordRow(
                id=str(item.id),
                run_id=str(run_id),
                evidence_type=item.evidence_type,
                source=item.source,
                observed_at=item.observed_at,
                summary=item.summary,
                raw_reference=item.raw_reference,
                integrity_sha256=item.integrity_sha256,
                confidence=item.confidence,
                confirmed=item.confirmed,
                payload_json={},
                created_at=item.observed_at,
            )
            for item in evidence
        ]
        self._ensure_sqlite_outer_transaction(session)
        try:
            with session.begin_nested():
                session.add_all(rows)
                self._append_audit(
                    session,
                    incident_id=UUID(run.incident_id),
                    run_id=run_id,
                    event_type="evidence_collected",
                    request_id=request_id,
                    occurred_at=max(item.observed_at for item in evidence),
                    payload={
                        "evidence_ids": [str(item.id) for item in evidence],
                        "count": len(evidence),
                    },
                )
                session.flush()
        except IntegrityError as error:
            is_id_conflict = self._matches_integrity_error(
                error,
                constraint_name="evidence_records_pkey",
                sqlite_signature="evidence_records.id",
            )
            is_digest_conflict = self._matches_integrity_error(
                error,
                constraint_name="uq_evidence_run_integrity",
                sqlite_signature=(
                    "evidence_records.run_id, evidence_records.integrity_sha256"
                ),
            )
            if not is_id_conflict and not is_digest_conflict:
                raise
            duplicate = self._find_duplicate_evidence(session, run_id, evidence)
            if duplicate is None:
                raise
            raise DuplicateEvidence(duplicate) from None

    def save_assessment(
        self,
        session: Session,
        run_id: UUID,
        assessment: Assessment,
        *,
        request_id: str,
        now: datetime,
    ) -> None:
        row = self._require_run(session, run_id, lock=True)
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            row.assessment_json = {
                "conclusion": assessment.conclusion.value,
                "risk_level": assessment.risk_level.value,
                "rule_ids": list(assessment.rule_ids),
                "evidence_ids": [str(value) for value in assessment.evidence_ids],
                "recommended_action": assessment.recommended_action,
                "explanation": assessment.explanation,
            }
            row.updated_at = now
            self._append_audit(
                session,
                incident_id=UUID(row.incident_id),
                run_id=run_id,
                event_type="assessment_completed",
                request_id=request_id,
                occurred_at=now,
                payload={
                    "conclusion": assessment.conclusion.value,
                    "risk_level": assessment.risk_level.value,
                    "evidence_count": len(assessment.evidence_ids),
                },
            )
            session.flush()

    def get_tool_result(
        self, session: Session, idempotency_key: str
    ) -> ToolResult | None:
        row = session.execute(
            select(SimulationToolCallRow).where(
                SimulationToolCallRow.idempotency_key == idempotency_key
            )
        ).scalar_one_or_none()
        return _tool_result_from_row(row) if row is not None else None

    def apply_tool_outcome(
        self,
        session: Session,
        run_id: UUID,
        outcome: BlockOutcome,
        *,
        request_id: str,
        now: datetime,
    ) -> ToolResult:
        stored = self.get_tool_result(session, outcome.result.idempotency_key)
        if stored is not None:
            return stored
        run = self._require_run(session, run_id)
        if (
            outcome.state.simulation_id != UUID(run.simulation_instance_id)
            or outcome.state.incident_id != UUID(run.incident_id)
        ):
            raise RunSimulationMismatch(run_id, outcome.state.simulation_id)
        simulation = session.execute(
            select(SimulationInstanceRow)
            .where(SimulationInstanceRow.id == str(outcome.state.simulation_id))
            .with_for_update()
        ).scalar_one_or_none()
        if simulation is None:
            raise SimulationNotFound(outcome.state.simulation_id)
        tool_row = SimulationToolCallRow(
            id=str(uuid4()),
            run_id=str(run_id),
            simulation_instance_id=simulation.id,
            tool_name=outcome.result.tool_name,
            target=outcome.result.target,
            idempotency_key=outcome.result.idempotency_key,
            status=outcome.result.status.value,
            before_state_json=dict(outcome.result.before_state),
            after_state_json=dict(outcome.result.after_state),
            error_code=outcome.result.error_code,
            requested_at=now,
            completed_at=now,
        )
        self._ensure_sqlite_outer_transaction(session)
        try:
            with session.begin_nested():
                simulation.connection_status = outcome.state.connection_status
                simulation.firewall_status = outcome.state.firewall_status
                simulation.fail_block_consumed = outcome.state.fail_block_consumed
                simulation.updated_at = outcome.state.updated_at
                session.add(tool_row)
                self._append_audit(
                    session,
                    incident_id=UUID(run.incident_id),
                    run_id=run_id,
                    event_type="tool_called",
                    request_id=request_id,
                    occurred_at=now,
                    payload={
                        "tool_call_id": tool_row.id,
                        "tool_name": outcome.result.tool_name,
                        "status": outcome.result.status.value,
                        "error_code": outcome.result.error_code,
                    },
                )
                session.flush()
        except IntegrityError as error:
            if not self._matches_integrity_error(
                error,
                constraint_name="uq_tool_call_idempotency_key",
                sqlite_signature="simulation_tool_calls.idempotency_key",
            ):
                raise
            raise DuplicateIdempotencyKey(outcome.result.idempotency_key) from None
        return outcome.result

    def save_verification(
        self,
        session: Session,
        run_id: UUID,
        result: VerificationResult,
        *,
        request_id: str,
    ) -> None:
        row = self._require_run(session, run_id, lock=True)
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            row.verification_json = {
                "blocked": result.blocked,
                "connection_stopped": result.connection_stopped,
                "observed_at": result.observed_at.isoformat(),
                "evidence_ids": [str(value) for value in result.evidence_ids],
            }
            self._append_audit(
                session,
                incident_id=UUID(row.incident_id),
                run_id=run_id,
                event_type="verification_completed",
                request_id=request_id,
                occurred_at=result.observed_at,
                payload={
                    "blocked": result.blocked,
                    "connection_stopped": result.connection_stopped,
                    "evidence_count": len(result.evidence_ids),
                },
            )
            session.flush()

    def get_incident(
        self, session: Session, incident_id: UUID
    ) -> IncidentDetail | None:
        row = session.get(IncidentRow, str(incident_id))
        return _incident_from_row(row) if row is not None else None

    def list_audit(
        self, session: Session, incident_id: UUID
    ) -> Sequence[AuditEvent]:
        exists = session.get(IncidentRow, str(incident_id))
        if exists is None:
            raise IncidentNotFound(incident_id)
        rows = session.execute(
            select(AuditEventRow)
            .where(AuditEventRow.incident_id == str(incident_id))
            .order_by(AuditEventRow.sequence.asc())
        ).scalars()
        return tuple(
            AuditEvent(
                id=UUID(row.id),
                incident_id=UUID(row.incident_id),
                run_id=UUID(row.run_id) if row.run_id is not None else None,
                event_type=row.event_type,
                request_id=row.request_id,
                occurred_at=_utc(row.occurred_at),
                payload=dict(row.payload_json),
            )
            for row in rows
        )

    def mark_recoverable_runs_interrupted(
        self, session: Session, *, request_id: str, now: datetime
    ) -> int:
        rows = tuple(
            session.execute(
                select(InvestigationRunRow)
                .where(
                    InvestigationRunRow.status.in_(
                        [status.value for status in _RECOVERABLE_STATUSES]
                    )
                )
                .with_for_update()
            ).scalars()
        )
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            for row in rows:
                current = row.status
                row.status = InvestigationStatus.INTERRUPTED.value
                row.updated_at = now
                row.completed_at = now
                self._append_audit(
                    session,
                    incident_id=UUID(row.incident_id),
                    run_id=UUID(row.id),
                    event_type="status_changed",
                    request_id=request_id,
                    occurred_at=now,
                    payload={
                        "from_status": current,
                        "to_status": InvestigationStatus.INTERRUPTED.value,
                    },
                )
            session.flush()
        return len(rows)

    @staticmethod
    def _require_run(
        session: Session, run_id: UUID, *, lock: bool = False
    ) -> InvestigationRunRow:
        statement = select(InvestigationRunRow).where(
            InvestigationRunRow.id == str(run_id)
        )
        if lock:
            statement = statement.with_for_update()
        row = session.execute(statement).scalar_one_or_none()
        if row is None:
            raise InvestigationNotFound(run_id)
        return row

    @staticmethod
    def _append_audit(
        session: Session,
        *,
        incident_id: UUID,
        run_id: UUID | None,
        event_type: str,
        request_id: str,
        occurred_at: datetime,
        payload: dict[str, Any],
    ) -> None:
        next_sequence = session.execute(
            update(IncidentRow)
            .where(IncidentRow.id == str(incident_id))
            .values(next_audit_sequence=IncidentRow.next_audit_sequence + 1)
            .returning(IncidentRow.next_audit_sequence)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if next_sequence is None:
            raise IncidentNotFound(incident_id)
        session.add(
            AuditEventRow(
                id=str(uuid4()),
                incident_id=str(incident_id),
                run_id=str(run_id) if run_id is not None else None,
                sequence=next_sequence - 1,
                event_type=event_type,
                request_id=request_id,
                occurred_at=occurred_at,
                payload_json=payload,
            )
        )

    @staticmethod
    def _ensure_sqlite_outer_transaction(session: Session) -> None:
        connection = session.connection()
        if connection.dialect.name != "sqlite":
            return
        driver_connection = connection.connection.driver_connection
        if not driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN")

    @staticmethod
    def _matches_integrity_error(
        error: IntegrityError,
        *,
        constraint_name: str | None,
        sqlite_signature: str,
    ) -> bool:
        diagnostic = getattr(error.orig, "diag", None)
        actual_name = getattr(diagnostic, "constraint_name", None)
        if constraint_name is not None and actual_name == constraint_name:
            return True
        return (
            "UNIQUE constraint failed:" in str(error.orig)
            and sqlite_signature in str(error.orig)
        )

    @staticmethod
    def _find_duplicate_evidence(
        session: Session, run_id: UUID, evidence: Sequence[Evidence]
    ) -> UUID | None:
        seen_ids: set[UUID] = set()
        seen_digests: set[str] = set()
        for item in evidence:
            if item.id in seen_ids or item.integrity_sha256 in seen_digests:
                return item.id
            seen_ids.add(item.id)
            seen_digests.add(item.integrity_sha256)

        stored = tuple(
            session.execute(
                select(EvidenceRecordRow.id, EvidenceRecordRow.integrity_sha256).where(
                    or_(
                        EvidenceRecordRow.id.in_([str(item.id) for item in evidence]),
                        (
                            (EvidenceRecordRow.run_id == str(run_id))
                            & EvidenceRecordRow.integrity_sha256.in_(
                                [item.integrity_sha256 for item in evidence]
                            )
                        ),
                    )
                )
            )
        )
        stored_ids = {UUID(row.id) for row in stored}
        stored_digests = {row.integrity_sha256 for row in stored}
        for item in evidence:
            if item.id in stored_ids or item.integrity_sha256 in stored_digests:
                return item.id
        return None
