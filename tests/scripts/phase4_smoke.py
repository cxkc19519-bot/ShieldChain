"""Offline Phase 4 multi-agent orchestration and trajectory smoke harness."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.context import ContextAssemblyService
from shieldchain.agents.domain import (
    AgentOutput,
    AgentRole,
    BudgetSnapshot,
    CasePhase,
    EvidenceReference,
)
from shieldchain.agents.orchestrator import (
    AtomicStepBundle,
    OrchestrationState,
    OrchestrationStatus,
    SuperagentOrchestrator,
)
from shieldchain.agents.persistence import (
    AgentExecutionRow,
    AgentHandoffRow,
    CaseContextRow,
)
from shieldchain.agents.roles import (
    ProfessionalRoleRegistry,
    RoleExecutionRequest,
    RoleExecutionResult,
    RoleExecutionStatus,
)
from shieldchain.agents.security import ServerAccessContext
from shieldchain.agents.trajectory import CollaborationTrajectoryQuery
from shieldchain.incidents.persistence import (
    AuditEventRow,
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.rag.domain import SensitivityLevel

NOW = datetime(2026, 7, 23, 4, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
CASE, RUN, SIMULATION, EVIDENCE = (UUID(int=value) for value in (801, 802, 803, 804))
SHA = "b" * 64


class OfflineContexts:
    def build(
        self, *, state: OrchestrationState, role: AgentRole
    ) -> RoleExecutionRequest:
        context = ContextAssemblyService(now=NOW).assemble(
            access=ServerAccessContext(
                TENANT,
                uuid4(),
                role,
                ("analyst",),
                (SensitivityLevel.INTERNAL,),
                ("soc",),
            ),
            system_rules=("Follow deterministic workflow",),
            safety_boundaries=("Never execute tools",),
            current_task="Investigate the fixed phishing alert",
            allowed_actions=("block_ip",),
            case_tenant_id=TENANT,
            case_sensitivity=SensitivityLevel.INTERNAL,
            case_permission_tags=("soc",),
            case_summary={
                "case_id": str(CASE),
                "confirmed_facts": ["outbound connection"],
            },
            candidates=(),
            output_schema={"summary": "string"},
            max_tokens=1000,
        )
        return RoleExecutionRequest(role, state.case_id, context, NOW)


class OfflineRole:
    def __init__(self, role: AgentRole) -> None:
        self.role = role

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        reference = EvidenceReference(EVIDENCE, CASE, "siem:alert-1", NOW, SHA)
        output = AgentOutput(
            self.role,
            CASE,
            f"Offline {self.role.value} completed",
            (reference,),
            (),
            (),
            (),
            NOW,
        )
        return RoleExecutionResult(RoleExecutionStatus.COMPLETED, output)


class SQLiteAtomicCommit:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self.factory = factory

    def commit(self, bundle: AtomicStepBundle) -> None:
        with self.factory.begin() as session:
            context = session.execute(
                select(CaseContextRow).where(CaseContextRow.run_id == str(RUN))
            ).scalar_one()
            incident = session.get(IncidentRow, str(CASE))
            assert incident is not None
            if context.revision != bundle.expected_revision:
                raise RuntimeError("stale smoke revision")
            if bundle.output is not None:
                session.add(
                    AgentExecutionRow(
                        id=str(uuid5(NAMESPACE_URL, f"{bundle.id}:output")),
                        run_id=str(RUN),
                        tenant_id=str(TENANT),
                        role=bundle.output.role.value,
                        summary=bundle.output.summary,
                        references_json=[
                            item.to_dict() for item in bundle.output.references
                        ],
                        hypotheses_json=[],
                        risks_json=[],
                        recommended_actions_json=list(
                            bundle.output.recommended_actions
                        ),
                        termination_reason=bundle.output.termination_reason.value,
                        created_at=bundle.output.created_at,
                    )
                )
            if bundle.handoff is not None:
                session.add(
                    AgentHandoffRow(
                        id=str(bundle.handoff.id),
                        run_id=str(RUN),
                        tenant_id=str(TENANT),
                        sender_role=bundle.handoff.sender.value,
                        receiver_role=bundle.handoff.receiver.value,
                        conclusion=bundle.handoff.conclusion,
                        references_json=[
                            item.to_dict() for item in bundle.handoff.references
                        ],
                        confidence=bundle.handoff.confidence,
                        open_questions_json=list(bundle.handoff.open_questions),
                        recommended_actions_json=list(
                            bundle.handoff.recommended_actions
                        ),
                        created_at=bundle.handoff.created_at,
                    )
                )
            session.add(
                AuditEventRow(
                    id=str(uuid5(NAMESPACE_URL, f"{bundle.id}:audit")),
                    incident_id=str(CASE),
                    run_id=str(RUN),
                    sequence=incident.next_audit_sequence,
                    event_type=bundle.audit.event_type,
                    request_id="phase4-smoke",
                    occurred_at=bundle.created_at,
                    payload_json={
                        "from_phase": bundle.audit.from_phase.value,
                        "to_phase": bundle.audit.to_phase.value,
                        "result_status": bundle.audit.result_status,
                    },
                )
            )
            incident.next_audit_sequence += 1
            context.phase = bundle.audit.to_phase.value
            context.revision = bundle.next_revision
            context.budget_json = bundle.budget.to_dict()
            context.step_status_json = {
                **context.step_status_json,
                bundle.audit.role.value
                if bundle.audit.role
                else "supervisor": bundle.audit.result_status,
            }
            context.disposition_status = "Offline collaboration in progress"
            context.updated_at = bundle.created_at


def seed(factory: sessionmaker[Session]) -> None:
    budget = BudgetSnapshot(10, 0, 2, 0, 60, 0, 10_000, 0, 1.0, 0.0, 0, 0)
    with factory.begin() as session:
        session.add(
            SimulationInstanceRow(
                id=str(SIMULATION),
                scenario_key="phase4-smoke",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="PHASE4-SMOKE",
                simulation_instance_id=str(SIMULATION),
                alert_id="ALERT-SMOKE",
                alert_status="open",
                endpoint="offline-host",
                username="analyst",
                source_ip="10.0.0.1",
                remote_ip="203.0.113.8",
                remote_port=443,
                process_name="powershell.exe",
                parent_process_name="explorer.exe",
                command_summary="offline fixture",
                threat_label="phishing",
                created_at=NOW,
            )
        )
        session.flush()
        session.add(
            InvestigationRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                incident_id=str(CASE),
                simulation_instance_id=str(SIMULATION),
                status="analyzing",
                mode="normal",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            EvidenceRecordRow(
                id=str(EVIDENCE),
                run_id=str(RUN),
                evidence_type="alert",
                source="siem",
                observed_at=NOW,
                summary="fixed alert",
                raw_reference="siem:alert-1",
                integrity_sha256=SHA,
                confidence=1.0,
                confirmed=True,
                payload_json={},
                created_at=NOW,
            )
        )
        session.add(
            CaseContextRow(
                id=str(RUN),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                revision=0,
                phase="triage",
                user_goal="hidden operator goal",
                hypotheses_json=[],
                risks_json=[],
                plan_json=["triage", "investigate"],
                step_status_json={},
                disposition_status="Offline collaboration started",
                budget_json=budget.to_dict(),
                created_at=NOW,
                updated_at=NOW,
            )
        )


def run(database: Path) -> None:
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(bind=engine)
    seed(factory)
    roles = ProfessionalRoleRegistry({role: OfflineRole(role) for role in AgentRole})
    subject = SuperagentOrchestrator(
        roles=roles, contexts=OfflineContexts(), commits=SQLiteAtomicCommit(factory)
    )
    state = OrchestrationState(
        CASE,
        CasePhase.TRIAGE,
        OrchestrationStatus.RUNNING,
        BudgetSnapshot(10, 0, 2, 0, 60, 0, 10_000, 0, 1.0, 0.0, 0, 0),
        0,
        False,
    )
    first = subject.advance(state)
    second = subject.advance(first.state)
    if not first.committed or not second.committed:
        raise RuntimeError("offline orchestration did not commit")
    view = CollaborationTrajectoryQuery(factory).get(tenant_id=TENANT, run_id=RUN)
    serialized = view.model_dump_json()
    if view.revision != 2 or len(view.handoffs) != 2 or len(view.citations) != 1:
        raise RuntimeError("trajectory projection is incomplete")
    for forbidden in (
        "hidden operator goal",
        "raw_prompt",
        "chain_of_thought",
        "tenant_id",
    ):
        if forbidden in serialized:
            raise RuntimeError(f"public trajectory leaked forbidden field: {forbidden}")
    engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    run(parser.parse_args().database)
    print("Phase 4 offline orchestration and public trajectory smoke passed.")
