"""Offline Phase 5 trusted-tool gateway and recovery smoke harness."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.domain import (
    AgentRole,
    BudgetSnapshot,
    CasePhase,
    EvidenceReference,
)
from shieldchain.agents.orchestrator import (
    OrchestrationState,
    OrchestrationStatus,
    SuperagentOrchestrator,
    SupervisorReason,
)
from shieldchain.incidents.persistence import (
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.tools.api_service import TrustedToolApiService
from shieldchain.tools.domain import (
    ApprovalOutcome,
    ExecutionOutcome,
    ToolTargetType,
    TrustedToolCallStatus,
    TrustedToolRequest,
)
from shieldchain.tools.gateway import TrustedToolGateway
from shieldchain.tools.gateway_store import SqlAlchemyGatewayStore
from shieldchain.tools.policy import ToolExecutionMode, ToolPolicyContext
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.repositories import (
    SqlAlchemyTrustedToolRepository,
    TrustedToolIdempotencyConflict,
)
from shieldchain.tools.simulation import OfflineSimulationAdapter

NOW = datetime(2026, 7, 23, 12, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
ACTOR = UUID("00000000-0000-4000-8000-000000000002")
CASE, RUN, SIMULATION, EVIDENCE = (UUID(int=value) for value in range(5101, 5105))
SHA = "e" * 64


class TimeoutAdapter:
    def execute(self, _request):
        raise TimeoutError("fixed offline timeout")

    def verify(self, _request, _execution, *, now):
        raise AssertionError("unknown execution must not be verified")


class Commits:
    def __init__(self) -> None:
        self.items = []

    def commit(self, bundle) -> None:
        self.items.append(bundle)


def seed(session: Session) -> None:
    session.add(
        SimulationInstanceRow(
            id=str(SIMULATION),
            scenario_key="phase5-smoke",
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
            external_id="INC-PHASE5",
            simulation_instance_id=str(SIMULATION),
            alert_id="ALT-PHASE5",
            alert_status="open",
            endpoint="endpoint-42",
            username="user-42",
            source_ip="10.0.0.5",
            remote_ip="203.0.113.8",
            remote_port=443,
            process_name="powershell.exe",
            parent_process_name="outlook.exe",
            command_summary="fixed simulation",
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
            status="action_planned",
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
            evidence_type="network",
            source="siem",
            observed_at=NOW,
            summary="confirmed malicious target",
            raw_reference="siem:phase5",
            integrity_sha256=SHA,
            confidence=1.0,
            confirmed=True,
            payload_json={},
            created_at=NOW,
        )
    )
    session.commit()


def bound(number: int, key: str, target: str = "203.0.113.8"):
    request = TrustedToolRequest(
        UUID(int=number),
        CASE,
        RUN,
        ACTOR,
        key,
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": target, "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Remove exact rule after review.",
        (EvidenceReference(EVIDENCE, CASE, "siem:phase5", NOW, SHA),),
        NOW,
    )
    return default_tool_registry().bind(request)


def context(
    *, mode: ToolExecutionMode = ToolExecutionMode.SIMULATION
) -> ToolPolicyContext:
    registry = default_tool_registry()
    return ToolPolicyContext(
        tenant_id=TENANT,
        principal_id=ACTOR,
        case_id=CASE,
        run_id=RUN,
        role=AgentRole.RESPONSE_PLANNING,
        mode=mode,
        automation_enabled=True,
        emergency_stop_active=False,
        allowed_tools=frozenset(
            item.definition.identity for item in registry.registrations
        ),
        allowed_targets={
            ToolTargetType.IPV4: frozenset({"203.0.113.8", "203.0.113.9"})
        },
        confirmed_evidence_ids=frozenset({EVIDENCE}),
        tool_calls_used=0,
        tool_call_limit=10,
        calls_in_window=0,
        rate_limit=10,
        simulation_auto_approve_critical=False,
        now=NOW,
    )


def waiting_state() -> OrchestrationState:
    return OrchestrationState(
        CASE,
        CasePhase.AWAITING_EXECUTION,
        OrchestrationStatus.AWAITING_TRUSTED_EXECUTION,
        BudgetSnapshot(10, 1, 2, 0, 60, 1, 10_000, 100, 1.0, 0.0, 10, 1),
        1,
        False,
        SupervisorReason.TRUSTED_EXECUTION_REQUIRED,
    )


def run(database: Path) -> None:
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(bind=engine)
    with factory() as session:
        seed(session)
        adapter = OfflineSimulationAdapter(
            initialized_at=NOW,
            firewall_targets=frozenset({"203.0.113.8"}),
            endpoint_targets=frozenset({"endpoint-42"}),
            account_targets=frozenset({"user-42"}),
        )
        success_bound = bound(5110, "phase5:success")
        success = TrustedToolGateway().submit(
            bound=success_bound,
            context=context(),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id="phase5-success",
        )
        if (
            success.call.status is not TrustedToolCallStatus.SUCCEEDED
            or success.verification is None
        ):
            raise RuntimeError("verified gateway execution did not succeed")
        duplicate = TrustedToolGateway().submit(
            bound=success_bound,
            context=context(),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id="phase5-duplicate",
        )
        if duplicate.created or duplicate.call.revision != success.call.revision:
            raise RuntimeError("idempotent replay changed the trusted call")
        try:
            SqlAlchemyTrustedToolRepository().create_or_get(
                session,
                tenant_id=TENANT,
                bound=bound(5111, "phase5:success", "203.0.113.9"),
                request_id="phase5-conflict",
            )
        except TrustedToolIdempotencyConflict:
            pass
        else:
            raise RuntimeError("same-key digest conflict was accepted")

        unknown = TrustedToolGateway().submit(
            bound=bound(5120, "phase5:unknown"),
            context=context(),
            store=SqlAlchemyGatewayStore(session),
            adapter=TimeoutAdapter(),
            request_id="phase5-unknown",
        )
        if (
            unknown.call.status is not TrustedToolCallStatus.NEEDS_REVIEW
            or unknown.attempt is None
            or unknown.attempt.outcome is not ExecutionOutcome.UNKNOWN
        ):
            raise RuntimeError("unknown mutating outcome did not fail closed")

        approval_required = TrustedToolGateway().submit(
            bound=bound(5125, "phase5:rejected"),
            context=context(mode=ToolExecutionMode.REAL),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id="phase5-await-approval",
        )
        if approval_required.call.status is not TrustedToolCallStatus.AWAITING_APPROVAL:
            raise RuntimeError("real mutation did not require human approval")
        rejected_id = approval_required.call.request.id

        pending, _ = SqlAlchemyTrustedToolRepository().create_or_get(
            session,
            tenant_id=TENANT,
            bound=bound(5130, "phase5:emergency"),
            request_id="phase5-emergency-create",
        )
        session.commit()

    api = TrustedToolApiService(factory)
    rejected = api.decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        call_id=rejected_id,
        outcome=ApprovalOutcome.REJECTED,
        reason="offline smoke rejection",
        now=NOW,
    )
    if rejected.status != TrustedToolCallStatus.REJECTED.value:
        raise RuntimeError("human rejection did not terminate the call")

    api.emergency(
        tenant_id=TENANT,
        actor_id=ACTOR,
        active=True,
        reason="offline smoke emergency",
        now=NOW,
    )
    with factory() as session:
        stopped = SqlAlchemyTrustedToolRepository().get(
            session, tenant_id=TENANT, tool_call_id=pending.request.id
        )
        if (
            stopped is None
            or stopped.status is not TrustedToolCallStatus.EMERGENCY_STOPPED
        ):
            raise RuntimeError("emergency stop did not stop pending work")
    api.emergency(
        tenant_id=TENANT,
        actor_id=ACTOR,
        active=False,
        reason="offline smoke reset",
        now=NOW,
    )

    trace = api.trace(tenant_id=TENANT, run_id=RUN).model_dump_json()
    for forbidden in (
        "tenant_id",
        "principal_id",
        "token_digest",
        "result_summary",
        "chain_of_thought",
        "raw_prompt",
    ):
        if forbidden in trace:
            raise RuntimeError(f"public tool trace leaked forbidden field: {forbidden}")

    commits = Commits()
    orchestrator = SuperagentOrchestrator(roles=None, contexts=None, commits=commits)  # type: ignore[arg-type]
    resumed = orchestrator.resume_after_execution(
        waiting_state(), call=success.call, verification=success.verification, now=NOW
    )
    if resumed.state.phase is not CasePhase.VERIFICATION or not resumed.committed:
        raise RuntimeError("verified execution did not resume orchestration")
    reviewed = orchestrator.resume_after_execution(
        waiting_state(), call=unknown.call, verification=None, now=NOW
    )
    if reviewed.state.phase is not CasePhase.NEEDS_REVIEW:
        raise RuntimeError("unknown execution did not route to manual review")
    engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    run(parser.parse_args().database)
    print("Phase 5 offline trusted-tool and recovery smoke passed.")
