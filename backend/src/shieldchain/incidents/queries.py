from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.incidents.persistence import (
    AuditEventRow,
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    InvestigationStepRow,
    SimulationInstanceRow,
    SimulationToolCallRow,
)
from shieldchain.incidents.ports import IncidentNotFound, InvestigationNotFound
from shieldchain.incidents.schemas import (
    AssessmentView,
    AuditEventView,
    AuditResponse,
    EvidenceView,
    IncidentResponse,
    IncidentView,
    InvestigationResponse,
    RunSummaryView,
    SimulationView,
    StepView,
    ToolResultView,
    VerificationView,
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _simulation(row: SimulationInstanceRow) -> SimulationView:
    return SimulationView(
        id=UUID(row.id),
        generation=row.generation,
        environment=row.environment,
        connection_status=row.connection_status,
        firewall_status=row.firewall_status,
        fail_block_consumed=row.fail_block_consumed,
    )


def _incident(row: IncidentRow) -> IncidentView:
    return IncidentView(
        id=UUID(row.id),
        external_id=row.external_id,
        simulation_instance_id=UUID(row.simulation_instance_id),
        alert_id=row.alert_id,
        alert_status=row.alert_status,
        endpoint=row.endpoint,
        username=row.username,
        source_ip=row.source_ip,
        remote_ip=row.remote_ip,
        remote_port=row.remote_port,
        process_name=row.process_name,
        parent_process_name=row.parent_process_name,
        command_summary=row.command_summary,
        threat_label=row.threat_label,
        created_at=_utc(row.created_at),
    )


def _run_summary(row: InvestigationRunRow) -> RunSummaryView:
    return RunSummaryView(
        run_id=UUID(row.id),
        status=row.status,
        mode=row.mode,
        created_at=_utc(row.created_at),
        updated_at=_utc(row.updated_at),
        completed_at=_utc(row.completed_at) if row.completed_at is not None else None,
    )


class IncidentQueryService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def investigation(self, run_id: UUID) -> InvestigationResponse:
        with self._session_factory() as session:
            run = session.get(InvestigationRunRow, str(run_id))
            if run is None:
                raise InvestigationNotFound(run_id)
            simulation = session.get(SimulationInstanceRow, run.simulation_instance_id)
            incident = session.get(IncidentRow, run.incident_id)
            if simulation is None or incident is None:
                raise InvestigationNotFound(run_id)
            steps = tuple(
                session.scalars(
                    select(InvestigationStepRow)
                    .where(InvestigationStepRow.run_id == str(run_id))
                    .order_by(InvestigationStepRow.started_at, InvestigationStepRow.id)
                )
            )
            evidence = tuple(
                session.scalars(
                    select(EvidenceRecordRow)
                    .where(EvidenceRecordRow.run_id == str(run_id))
                    .order_by(EvidenceRecordRow.observed_at, EvidenceRecordRow.id)
                )
            )
            tools = tuple(
                session.scalars(
                    select(SimulationToolCallRow)
                    .where(SimulationToolCallRow.run_id == str(run_id))
                    .order_by(SimulationToolCallRow.requested_at, SimulationToolCallRow.id)
                )
            )
            assessment = (
                AssessmentView.model_validate(run.assessment_json)
                if run.assessment_json is not None
                else None
            )
            verification = (
                VerificationView.model_validate(run.verification_json)
                if run.verification_json is not None
                else None
            )
            tool = tools[-1] if tools else None
            return InvestigationResponse(
                run_id=UUID(run.id),
                incident_id=UUID(run.incident_id),
                simulation_instance_id=UUID(run.simulation_instance_id),
                status=run.status,
                mode=run.mode,
                created_at=_utc(run.created_at),
                updated_at=_utc(run.updated_at),
                completed_at=_utc(run.completed_at) if run.completed_at is not None else None,
                simulation=_simulation(simulation),
                steps=[
                    StepView(
                        step_key=row.step_key,
                        status=row.status,
                        detail=dict(row.detail_json),
                        error_code=row.error_code,
                        started_at=_utc(row.started_at),
                        completed_at=(
                            _utc(row.completed_at) if row.completed_at is not None else None
                        ),
                    )
                    for row in steps
                ],
                evidence=[
                    EvidenceView(
                        id=UUID(row.id),
                        evidence_type=row.evidence_type,
                        source=row.source,
                        observed_at=_utc(row.observed_at),
                        summary=row.summary,
                        raw_reference=row.raw_reference,
                        integrity_sha256=row.integrity_sha256,
                        confidence=row.confidence,
                        confirmed=row.confirmed,
                        payload=dict(row.payload_json),
                    )
                    for row in evidence
                ],
                assessment=assessment,
                tool_result=(
                    ToolResultView(
                        tool_name=tool.tool_name,
                        target=tool.target,
                        idempotency_key=tool.idempotency_key,
                        status=tool.status,
                        before_state=dict(tool.before_state_json),
                        after_state=dict(tool.after_state_json),
                        error_code=tool.error_code,
                    )
                    if tool is not None
                    else None
                ),
                verification=verification,
            )

    def incident(self, incident_id: UUID) -> IncidentResponse:
        with self._session_factory() as session:
            incident = session.get(IncidentRow, str(incident_id))
            if incident is None:
                raise IncidentNotFound(incident_id)
            runs = tuple(
                session.scalars(
                    select(InvestigationRunRow)
                    .where(InvestigationRunRow.incident_id == str(incident_id))
                    .order_by(InvestigationRunRow.created_at, InvestigationRunRow.id)
                )
            )
            return IncidentResponse(
                incident=_incident(incident), runs=[_run_summary(row) for row in runs]
            )

    def audit(self, incident_id: UUID) -> AuditResponse:
        with self._session_factory() as session:
            if session.get(IncidentRow, str(incident_id)) is None:
                raise IncidentNotFound(incident_id)
            rows = tuple(
                session.scalars(
                    select(AuditEventRow)
                    .where(AuditEventRow.incident_id == str(incident_id))
                    .order_by(AuditEventRow.sequence)
                )
            )
            return AuditResponse(
                incident_id=incident_id,
                events=[
                    AuditEventView(
                        id=UUID(row.id),
                        sequence=row.sequence,
                        event_type=row.event_type,
                        request_id=row.request_id,
                        occurred_at=_utc(row.occurred_at),
                        payload=dict(row.payload_json),
                    )
                    for row in rows
                ],
            )

    def latest_run_for_simulation(self, simulation_id: UUID) -> RunSummaryView | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(InvestigationRunRow)
                .where(InvestigationRunRow.simulation_instance_id == str(simulation_id))
                .order_by(InvestigationRunRow.created_at.desc(), InvestigationRunRow.id.desc())
                .limit(1)
            )
            return _run_summary(row) if row is not None else None
