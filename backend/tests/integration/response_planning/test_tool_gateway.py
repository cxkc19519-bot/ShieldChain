from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from shieldchain.agents.persistence import AgentExecutionRow, AgentRunRow, CaseContextRow
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.persistence import (
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.react.domain import ReactLoopStatus
from shieldchain.react.persistence import (
    ReactAssessmentRow,
    ReactDecisionRow,
    ReactLoopRow,
    ReactObservationRow,
)
from shieldchain.react.repositories import SqlAlchemyReactRepository
from shieldchain.react.safety_loop import ResponseSafetyLoopService
from shieldchain.response_planning.persistence import (
    ResponsePlanActionRow,
    ResponsePlanEventRow,
    ResponsePlanRevisionRow,
    ResponsePlanRow,
)
from shieldchain.tools.api_service import TrustedToolApiService
from shieldchain.tools.domain import (
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyReason,
    ToolExecutionAttempt,
    ToolVerification,
    TrustedToolCallStatus,
    VerificationOutcome,
)
from shieldchain.tools.execution_store import ExecutionLeaseConflict, SqlAlchemyExecutionStore
from shieldchain.tools.gateway import AdapterExecution
from shieldchain.tools.persistence import (
    ToolApprovalRow,
    ToolAutomationControlRow,
    ToolExecutionAttemptRow,
    TrustedToolCallRow,
)
from shieldchain.tools.plan_service import (
    ResponsePlanDecisionConflict,
    ResponsePlanDecisionNotFound,
    ResponsePlanToolService,
)
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.repositories import SqlAlchemyTrustedToolRepository, _call
from shieldchain.tools.simulation import OfflineSimulationAdapter

NOW = datetime(2026, 8, 23, 15, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
OTHER = UUID("00000000-0000-4000-8000-000000000099")
ACTOR = UUID("00000000-0000-4000-8000-000000000002")
CASE = UUID("00000000-0000-4000-8000-000000000301")
RUN = UUID("00000000-0000-4000-8000-000000000302")
SIMULATION = UUID("00000000-0000-4000-8000-000000000303")
EVIDENCE = UUID("00000000-0000-4000-8000-000000000304")
PLAN = UUID("00000000-0000-4000-8000-000000000305")
REVISION = UUID("00000000-0000-4000-8000-000000000306")
QUERY_ACTION = UUID("00000000-0000-4000-8000-000000000307")
BLOCK_ACTION = UUID("00000000-0000-4000-8000-000000000308")


@pytest.fixture
def plan_context(tmp_path: Path):
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'plan-tool-gateway.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        session.add(
            SimulationInstanceRow(
                id=str(SIMULATION),
                scenario_key="plan-tool-gateway",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="INC-PLAN-GATEWAY",
                simulation_instance_id=str(SIMULATION),
                alert_id="ALT-PLAN-GATEWAY",
                alert_status="open",
                endpoint="endpoint-plan",
                username="plan-user",
                source_ip="203.0.113.8",
                remote_ip="203.0.113.9",
                remote_port=443,
                process_name="agent",
                parent_process_name="system",
                command_summary="public summary",
                threat_label="confirmed",
                created_at=NOW,
            )
        )
        session.add(
            AgentRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                principal_id=str(ACTOR),
                run_kind="incident_investigation",
                status="running",
                goal="Accept a compiled response plan.",
                catalog_revision="trusted-tools-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
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
        session.add(
            CaseContextRow(
                id=str(CASE),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                revision=0,
                phase="response_planning",
                user_goal="Contain a confirmed source.",
                hypotheses_json=[],
                risks_json=[],
                plan_json=[],
                step_status_json={},
                disposition_status="open",
                budget_json={},
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
                summary="Confirmed malicious source.",
                raw_reference="siem:plan:1",
                integrity_sha256="e" * 64,
                confidence=1.0,
                confirmed=True,
                payload_json={"target_ip": "203.0.113.8"},
                created_at=NOW,
            )
        )
        session.add(
            AgentExecutionRow(
                id="00000000-0000-4000-8000-000000000309",
                run_id=str(RUN),
                tenant_id=str(TENANT),
                role="reporting",
                summary="Initial advisory report without execution facts.",
                references_json=[],
                hypotheses_json=[],
                risks_json=[],
                recommended_actions_json=[],
                termination_reason="completed",
                created_at=NOW,
            )
        )
        session.add(
            ResponsePlanRow(
                id=str(PLAN),
                tenant_id=str(TENANT),
                run_id=str(RUN),
                case_id=str(CASE),
                status="proposed",
                current_revision=0,
                created_by_role="response_planning",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            ResponsePlanRevisionRow(
                id=str(REVISION),
                plan_id=str(PLAN),
                tenant_id=str(TENANT),
                revision=0,
                parent_revision=None,
                public_summary="Query current state, then block the confirmed source.",
                assumptions_json=[],
                stop_conditions_json=["evidence conflict"],
                operator_notes_json=[],
                reason_code=None,
                model_id="test-model",
                prompt_policy_version="test-v1",
                created_at=NOW,
            )
        )
        session.flush()
        session.add_all(
            [
                ResponsePlanActionRow(
                    id=str(QUERY_ACTION),
                    plan_revision_id=str(REVISION),
                    tenant_id=str(TENANT),
                    sequence=1,
                    client_action_id="step-1",
                    tool_name="query_firewall_state",
                    tool_version="1",
                    target_reference_id=str(EVIDENCE),
                    target_type="ipv4",
                    target_identifier="203.0.113.8",
                    arguments_json={"target_ip": "203.0.113.8"},
                    expected_state_json={"firewall_status": "not_blocked"},
                    depends_on_json=[],
                    evidence_ids_json=[str(EVIDENCE)],
                    public_reason="Read the current state.",
                    verification_tool=None,
                    verification_version=None,
                    rollback_strategy="Read-only action requires no rollback.",
                    assessed_risk="read_only",
                    approval_required=False,
                    status="proposed",
                    created_at=NOW,
                ),
                ResponsePlanActionRow(
                    id=str(BLOCK_ACTION),
                    plan_revision_id=str(REVISION),
                    tenant_id=str(TENANT),
                    sequence=2,
                    client_action_id="step-2",
                    tool_name="block_ip",
                    tool_version="1",
                    target_reference_id=str(EVIDENCE),
                    target_type="ipv4",
                    target_identifier="203.0.113.8",
                    arguments_json={"target_ip": "203.0.113.8", "rule_ttl_seconds": 600},
                    expected_state_json={"firewall_status": "blocked"},
                    depends_on_json=[str(QUERY_ACTION)],
                    evidence_ids_json=[str(EVIDENCE)],
                    public_reason="Block the confirmed source after checking state.",
                    verification_tool="query_firewall_state",
                    verification_version="1",
                    rollback_strategy="Remove the exact firewall rule after review.",
                    assessed_risk="high",
                    approval_required=True,
                    status="proposed",
                    created_at=NOW,
                ),
            ]
        )
    yield ResponsePlanToolService(factory), factory
    engine.dispose()


def _accept(service: ResponsePlanToolService):
    return service.decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        plan_id=PLAN,
        outcome="accepted",
        reason="Reviewed the fixed plan and evidence.",
        now=NOW,
    )


def _adapter() -> OfflineSimulationAdapter:
    return OfflineSimulationAdapter(
        initialized_at=NOW,
        firewall_targets=frozenset({"203.0.113.8"}),
        endpoint_targets=frozenset(),
        account_targets=frozenset(),
    )


class NoopSafetyLoop:
    def advance_plan(self, **_values):
        return None

    def recover_stale(self, **_values):
        return ()


def _approve_block(factory, result) -> None:
    TrustedToolApiService(factory, safety_loop=NoopSafetyLoop()).decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        call_id=result.calls[1].call_id,
        outcome=ApprovalOutcome.APPROVED,
        reason="Approved fixed high-risk request.",
        now=NOW,
    )


class TimeoutBlockAdapter:
    def __init__(self) -> None:
        self.delegate = _adapter()
        self.block_calls = 0

    def execute(self, request):
        if request.registration.definition.name == "block_ip":
            self.block_calls += 1
            raise TimeoutError("private timeout")
        return self.delegate.execute(request)

    def verify(self, request, execution, *, now):
        return self.delegate.verify(request, execution, now=now)


class FailedBlockVerificationAdapter:
    def __init__(self) -> None:
        self.delegate = _adapter()

    def execute(self, request):
        return self.delegate.execute(request)

    def verify(self, request, execution, *, now):
        if request.registration.definition.name == "block_ip":
            return ToolVerification(
                uuid4(),
                request.request.id,
                VerificationOutcome.FAILED,
                {"firewall_status": "not_blocked"},
                request.request.evidence,
                PolicyReason.VERIFICATION_FAILED,
                now,
            )
        return self.delegate.verify(request, execution, now=now)


class FailedBlockExecutionAdapter:
    def __init__(self) -> None:
        self.delegate = _adapter()

    def execute(self, request):
        if request.registration.definition.name == "block_ip":
            return AdapterExecution(
                ExecutionOutcome.FAILED,
                "Sanitized simulated execution failure.",
                "simulated_failure",
            )
        return self.delegate.execute(request)

    def verify(self, request, execution, *, now):
        return self.delegate.verify(request, execution, now=now)


class InconclusiveBlockVerificationAdapter:
    def __init__(self) -> None:
        self.delegate = _adapter()

    def execute(self, request):
        return self.delegate.execute(request)

    def verify(self, request, execution, *, now):
        if request.registration.definition.name == "block_ip":
            raise RuntimeError("private verifier failure")
        return self.delegate.verify(request, execution, now=now)


class CountingAdapter:
    def __init__(self) -> None:
        self.delegate = _adapter()
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return self.delegate.execute(request)

    def verify(self, request, execution, *, now):
        return self.delegate.verify(request, execution, now=now)


class FixedAdapterProvider:
    def __init__(self, adapter) -> None:
        self.adapter = adapter

    def for_run(self, _session, **_values):
        return self.adapter


def test_plan_accept_creates_linked_calls_without_approving_high_risk_action(
    plan_context,
) -> None:
    service, factory = plan_context
    result = _accept(service)

    assert result.status == "awaiting_execution"
    assert [item.action_id for item in result.calls] == [QUERY_ACTION, BLOCK_ACTION]
    assert [item.status for item in result.calls] == ["approved", "awaiting_approval"]
    repeated = _accept(service)
    assert [item.call_id for item in repeated.calls] == [item.call_id for item in result.calls]
    with factory() as session:
        rows = list(
            session.scalars(select(TrustedToolCallRow).order_by(TrustedToolCallRow.created_at))
        )
        assert len(rows) == 2
        assert [row.plan_revision_id for row in rows] == [str(REVISION), str(REVISION)]
        assert [row.plan_action_id for row in rows] == [str(QUERY_ACTION), str(BLOCK_ACTION)]
        assert all(row.plan_id == str(PLAN) for row in rows)
        assert session.scalar(select(func.count()).select_from(ToolApprovalRow)) == 0
        events = list(
            session.scalars(
                select(ResponsePlanEventRow).where(
                    ResponsePlanEventRow.event_type == "plan_accepted"
                )
            )
        )
        assert len(events) == 1
        assert events[0].actor_subject_id == str(ACTOR)


def test_plan_reject_and_cross_tenant_decision_create_no_calls(plan_context) -> None:
    service, factory = plan_context
    with pytest.raises(ResponsePlanDecisionNotFound):
        service.decide(
            tenant_id=OTHER,
            actor_id=ACTOR,
            plan_id=PLAN,
            outcome="accepted",
            reason="cross tenant",
            now=NOW,
        )
    rejected = service.decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        plan_id=PLAN,
        outcome="rejected",
        reason="Evidence requires more review.",
        now=NOW,
    )
    assert rejected.status == "rejected"
    assert rejected.calls == []
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(TrustedToolCallRow)) == 0


def test_plan_accept_rechecks_target_evidence_and_rolls_back_atomically(plan_context) -> None:
    service, factory = plan_context
    with factory.begin() as session:
        session.get(EvidenceRecordRow, str(EVIDENCE)).payload_json = {"target_ip": "203.0.113.99"}

    with pytest.raises(ResponsePlanDecisionConflict, match="target evidence has changed"):
        _accept(service)
    with factory() as session:
        assert session.get(ResponsePlanRow, str(PLAN)).status == "proposed"
        assert session.scalar(select(func.count()).select_from(TrustedToolCallRow)) == 0
        assert session.scalar(select(func.count()).select_from(ResponsePlanEventRow)) == 0


def test_execution_lease_requires_verified_plan_dependencies_and_remains_unique(
    plan_context,
) -> None:
    service, factory = plan_context
    result = _accept(service)
    query_id, block_id = (item.call_id for item in result.calls)
    with factory.begin() as session:
        repo = SqlAlchemyTrustedToolRepository()
        query_call = repo.get(session, tenant_id=TENANT, tool_call_id=query_id)
        block_call = repo.get(session, tenant_id=TENANT, tool_call_id=block_id)
        assert query_call is not None and block_call is not None
        block_call = repo.transition(
            session,
            tenant_id=TENANT,
            current=block_call,
            target=TrustedToolCallStatus.APPROVED,
            now=NOW,
            request_id="test-approved-block",
        )
        execution = SqlAlchemyExecutionStore(session)
        with pytest.raises(ExecutionLeaseConflict, match="dependencies are not verified"):
            execution.acquire_lease(
                tenant_id=TENANT,
                call=block_call,
                holder_id=ACTOR,
                now=NOW,
                duration=timedelta(seconds=10),
                request_id="test-blocked-dependency",
            )
        query_call = repo.transition(
            session,
            tenant_id=TENANT,
            current=query_call,
            target=TrustedToolCallStatus.EXECUTING,
            now=NOW,
            request_id="test-query-executing",
        )
        query_call = repo.transition(
            session,
            tenant_id=TENANT,
            current=query_call,
            target=TrustedToolCallStatus.VERIFYING,
            now=NOW,
            request_id="test-query-verifying",
        )
        repo.append_verification(
            session,
            tenant_id=TENANT,
            verification=ToolVerification(
                uuid4(),
                query_call.request.id,
                VerificationOutcome.VERIFIED,
                {"firewall_status": "not_blocked"},
                query_call.request.evidence,
                None,
                NOW,
            ),
        )
        repo.transition(
            session,
            tenant_id=TENANT,
            current=query_call,
            target=TrustedToolCallStatus.SUCCEEDED,
            now=NOW,
            request_id="test-query-succeeded",
        )
        grant = execution.acquire_lease(
            tenant_id=TENANT,
            call=block_call,
            holder_id=ACTOR,
            now=NOW,
            duration=timedelta(seconds=10),
            request_id="test-block-lease",
        )
        assert grant.lease.request_id == block_id
        with pytest.raises(ExecutionLeaseConflict, match="already active"):
            execution.acquire_lease(
                tenant_id=TENANT,
                call=block_call,
                holder_id=ACTOR,
                now=NOW,
                duration=timedelta(seconds=10),
                request_id="test-block-duplicate-lease",
            )


def test_approval_digest_does_not_authorize_changed_action_parameters(plan_context) -> None:
    service, factory = plan_context
    result = _accept(service)
    block_id = result.calls[1].call_id
    TrustedToolApiService(factory, safety_loop=NoopSafetyLoop()).decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        call_id=block_id,
        outcome=ApprovalOutcome.APPROVED,
        reason="Approved the fixed request digest.",
        now=NOW,
    )
    with factory() as session:
        row = session.get(TrustedToolCallRow, str(block_id))
        approval = session.scalar(select(ToolApprovalRow))
        assert row is not None and approval is not None
        original = _call(row).request
        changed = replace(
            original,
            arguments={"target_ip": "203.0.113.8", "rule_ttl_seconds": 1200},
        )
        assert changed.request_digest != approval.request_digest
        assert approval.request_digest == row.request_digest


def test_safety_loop_completes_only_after_all_actions_are_verified(plan_context) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    adapter = _adapter()
    safety = ResponseSafetyLoopService(factory)

    waiting = safety.advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )
    assert waiting.plan_status == "awaiting_execution"
    assert waiting.loop_status is ReactLoopStatus.AWAITING_EXECUTION
    assert waiting.reason_code == "tool_approval_required"
    _approve_block(factory, accepted)
    completed = safety.advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert completed.plan_status == "completed"
    assert completed.loop_status is ReactLoopStatus.COMPLETED
    with factory() as session:
        assert session.get(ResponsePlanRow, str(PLAN)).status == "completed"
        assert session.get(AgentRunRow, str(RUN)).status == "completed"
        assert session.get(InvestigationRunRow, str(RUN)).status == "closed"
        assert session.get(CaseContextRow, str(CASE)).phase == "closed"
        reporting = session.scalar(
            select(AgentExecutionRow).where(AgentExecutionRow.role == "reporting")
        )
        assert reporting is not None
        assert "所有必需计划动作" in reporting.summary
        assert session.scalar(select(func.count()).select_from(ReactObservationRow)) == 2
        assert session.scalar(select(func.count()).select_from(ReactAssessmentRow)) == 2
        assert session.scalar(select(func.count()).select_from(ReactDecisionRow)) == 2
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ReactObservationRow)) == 2


def test_unknown_mutation_queries_state_without_replaying_change(plan_context) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    adapter = TimeoutBlockAdapter()
    safety = ResponseSafetyLoopService(factory)
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    _approve_block(factory, accepted)

    result = safety.advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert result.plan_status == "needs_review"
    assert result.loop_status is ReactLoopStatus.AWAITING_HUMAN
    assert result.reason_code == "execution_outcome_unknown_requires_operator"
    assert adapter.block_calls == 1
    with factory() as session:
        rows = list(session.scalars(select(TrustedToolCallRow)))
        assert [row.tool_name for row in rows].count("block_ip") == 1
        assert [row.tool_name for row in rows].count("query_firewall_state") == 2
        block = next(row for row in rows if row.tool_name == "block_ip")
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionAttemptRow)
                .where(ToolExecutionAttemptRow.tool_call_id == block.id)
            )
            == 1
        )


def test_verification_failure_creates_new_response_revision_and_stops(plan_context) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    adapter = FailedBlockVerificationAdapter()
    safety = ResponseSafetyLoopService(factory)
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    _approve_block(factory, accepted)

    result = safety.advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert result.plan_status == "needs_review"
    assert result.loop_status is ReactLoopStatus.AWAITING_HUMAN
    with factory() as session:
        plan = session.get(ResponsePlanRow, str(PLAN))
        revision = session.scalar(
            select(ResponsePlanRevisionRow).where(ResponsePlanRevisionRow.revision == 1)
        )
        assert plan.current_revision == 1
        assert revision is not None and revision.reason_code == "verification_failed"
        loop = session.scalar(select(ReactLoopRow))
        assert loop is not None and loop.status == "awaiting_human"


@pytest.mark.parametrize(
    ("adapter", "reason_code"),
    [
        (FailedBlockExecutionAdapter(), "execution_failed"),
        (InconclusiveBlockVerificationAdapter(), "verification_inconclusive"),
    ],
)
def test_terminal_failures_stop_with_stable_response_revision(
    plan_context, adapter, reason_code: str
) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    safety = ResponseSafetyLoopService(factory)
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    _approve_block(factory, accepted)

    result = safety.advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert result.plan_status == "needs_review"
    assert result.loop_status is ReactLoopStatus.AWAITING_HUMAN
    with factory() as session:
        revision = session.scalar(
            select(ResponsePlanRevisionRow).where(ResponsePlanRevisionRow.revision == 1)
        )
        assert revision is not None and revision.reason_code == reason_code


def test_rejected_tool_approval_moves_loop_to_human_review(plan_context) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    adapter = _adapter()
    safety = ResponseSafetyLoopService(factory)
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    TrustedToolApiService(factory, safety_loop=NoopSafetyLoop()).decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        call_id=accepted.calls[1].call_id,
        outcome=ApprovalOutcome.REJECTED,
        reason="Operator rejected the mutation.",
        now=NOW,
    )

    result = safety.advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert result.plan_status == "needs_review"
    assert result.loop_status is ReactLoopStatus.AWAITING_HUMAN
    with factory() as session:
        revision = session.scalar(
            select(ResponsePlanRevisionRow).where(ResponsePlanRevisionRow.revision == 1)
        )
        assert revision is not None and revision.reason_code == "approval_rejected"


def test_emergency_stop_blocks_dispatch_before_adapter_execution(plan_context) -> None:
    plan_service, factory = plan_context
    _accept(plan_service)
    with factory.begin() as session:
        session.add(
            ToolAutomationControlRow(
                tenant_id=str(TENANT),
                automation_enabled=False,
                emergency_stop_active=True,
                revision=1,
                actor_subject_id=str(ACTOR),
                reason="Emergency stop test.",
                updated_at=NOW,
            )
        )
    adapter = CountingAdapter()

    result = ResponseSafetyLoopService(factory).advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert result.reason_code == "emergency_stopped"
    assert result.loop_status is ReactLoopStatus.AWAITING_HUMAN
    assert adapter.calls == 0
    with factory() as session:
        revision = session.scalar(
            select(ResponsePlanRevisionRow).where(ResponsePlanRevisionRow.revision == 1)
        )
        assert revision is not None and revision.reason_code == "emergency_stopped"


def test_exhausted_loop_budget_stops_before_new_tool_call(plan_context) -> None:
    plan_service, factory = plan_context
    _accept(plan_service)
    with factory.begin() as session:
        session.add(
            ReactLoopRow(
                id="00000000-0000-4000-8000-000000000399",
                tenant_id=str(TENANT),
                case_id=str(CASE),
                run_id=str(RUN),
                status="running",
                revision=0,
                budget_json={
                    "step_limit": 1,
                    "steps_used": 1,
                    "loop_limit": 1,
                    "loops_used": 1,
                    "time_limit_seconds": 60,
                    "time_used_seconds": 1,
                    "token_limit": 100,
                    "tokens_used": 0,
                    "cost_limit_usd": 1,
                    "cost_used_usd": 0,
                    "tool_call_limit": 1,
                    "tool_calls_used": 1,
                },
                observation_fingerprints_json=[],
                started_at=NOW,
                updated_at=NOW,
            )
        )
    adapter = CountingAdapter()

    result = ResponseSafetyLoopService(factory).advance_plan(
        tenant_id=TENANT,
        plan_id=PLAN,
        now=NOW,
        adapter=adapter,
    )

    assert result.reason_code == "budget_exhausted"
    assert result.loop_status is ReactLoopStatus.AWAITING_HUMAN
    assert adapter.calls == 0


def test_tool_api_advances_plan_after_acceptance_and_approval(plan_context) -> None:
    _plan_service, factory = plan_context
    api = TrustedToolApiService(factory)

    accepted = api.decide_plan(
        tenant_id=TENANT,
        actor_id=ACTOR,
        plan_id=PLAN,
        outcome="accepted",
        reason="Accept and start the bounded safety loop.",
        now=NOW,
    )
    assert accepted.calls[1].status == "awaiting_approval"
    approved = api.decide(
        tenant_id=TENANT,
        actor_id=ACTOR,
        call_id=accepted.calls[1].call_id,
        outcome=ApprovalOutcome.APPROVED,
        reason="Approve the digest-bound mutation.",
        now=NOW,
    )

    assert approved.status == "succeeded"
    with factory() as session:
        assert session.get(ResponsePlanRow, str(PLAN)).status == "completed"
        assert session.scalar(select(ReactLoopRow.status)) == "completed"


def test_stale_mutating_execution_recovers_with_query_and_never_replays(plan_context) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    adapter = CountingAdapter()
    safety = ResponseSafetyLoopService(
        factory,
        adapters=FixedAdapterProvider(adapter),
    )
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    _approve_block(factory, accepted)
    block_id = accepted.calls[1].call_id
    with factory.begin() as session:
        repo = SqlAlchemyTrustedToolRepository()
        block = repo.get(session, tenant_id=TENANT, tool_call_id=block_id)
        assert block is not None
        block = repo.transition(
            session,
            tenant_id=TENANT,
            current=block,
            target=TrustedToolCallStatus.APPROVED,
            now=NOW,
            request_id="recovery-approved",
        )
        SqlAlchemyExecutionStore(session).acquire_lease(
            tenant_id=TENANT,
            call=block,
            holder_id=ACTOR,
            now=NOW,
            duration=timedelta(seconds=1),
            request_id="recovery-expiring-lease",
        )
        repo.transition(
            session,
            tenant_id=TENANT,
            current=block,
            target=TrustedToolCallStatus.EXECUTING,
            now=NOW,
            request_id="recovery-executing",
        )
        loop = SqlAlchemyReactRepository().get_by_run(
            session,
            tenant_id=TENANT,
            run_id=RUN,
        )
        assert loop is not None
        SqlAlchemyReactRepository().transition_status(
            session,
            tenant_id=TENANT,
            current=loop,
            target=ReactLoopStatus.RUNNING,
            now=NOW,
        )
    adapter.calls = 0

    recovered = safety.recover_stale(
        tenant_id=TENANT,
        now=NOW + timedelta(seconds=40),
        stale_after=timedelta(seconds=30),
    )

    assert len(recovered) == 1
    assert recovered[0].plan_status == "needs_review"
    assert recovered[0].loop_status is ReactLoopStatus.AWAITING_HUMAN
    assert adapter.calls == 1
    with factory() as session:
        rows = list(session.scalars(select(TrustedToolCallRow)))
        assert [row.tool_name for row in rows].count("block_ip") == 1
        assert [row.tool_name for row in rows].count("query_firewall_state") == 2
        original = session.get(TrustedToolCallRow, str(block_id))
        assert original.status == "needs_review"
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionAttemptRow)
                .where(ToolExecutionAttemptRow.tool_call_id == str(block_id))
            )
            == 0
        )


def test_stale_verifying_call_resumes_verification_without_reexecution(plan_context) -> None:
    plan_service, factory = plan_context
    accepted = _accept(plan_service)
    adapter = CountingAdapter()
    safety = ResponseSafetyLoopService(
        factory,
        adapters=FixedAdapterProvider(adapter),
    )
    safety.advance_plan(tenant_id=TENANT, plan_id=PLAN, now=NOW, adapter=adapter)
    _approve_block(factory, accepted)
    block_id = accepted.calls[1].call_id
    with factory.begin() as session:
        repo = SqlAlchemyTrustedToolRepository()
        execution = SqlAlchemyExecutionStore(session)
        block = repo.get(session, tenant_id=TENANT, tool_call_id=block_id)
        assert block is not None
        block = repo.transition(
            session,
            tenant_id=TENANT,
            current=block,
            target=TrustedToolCallStatus.APPROVED,
            now=NOW,
            request_id="verify-recovery-approved",
        )
        grant = execution.acquire_lease(
            tenant_id=TENANT,
            call=block,
            holder_id=ACTOR,
            now=NOW,
            duration=timedelta(seconds=10),
            request_id="verify-recovery-lease",
        )
        block = repo.transition(
            session,
            tenant_id=TENANT,
            current=block,
            target=TrustedToolCallStatus.EXECUTING,
            now=NOW,
            request_id="verify-recovery-executing",
        )
        bound = default_tool_registry().bind(block.request)
        outcome = adapter.execute(bound)
        assert outcome.outcome is ExecutionOutcome.SUCCEEDED
        repo.append_attempt(
            session,
            tenant_id=TENANT,
            attempt=ToolExecutionAttempt(
                uuid4(),
                block.request.id,
                1,
                outcome.outcome,
                outcome.result_summary,
                None,
                NOW,
                NOW,
            ),
        )
        execution.release_lease(
            tenant_id=TENANT,
            call=block,
            grant=grant,
            now=NOW,
            reason="adapter_succeeded",
            request_id="verify-recovery-release",
        )
        repo.transition(
            session,
            tenant_id=TENANT,
            current=block,
            target=TrustedToolCallStatus.VERIFYING,
            now=NOW,
            request_id="verify-recovery-verifying",
        )
        loop = SqlAlchemyReactRepository().get_by_run(
            session,
            tenant_id=TENANT,
            run_id=RUN,
        )
        assert loop is not None
        SqlAlchemyReactRepository().transition_status(
            session,
            tenant_id=TENANT,
            current=loop,
            target=ReactLoopStatus.RUNNING,
            now=NOW,
        )
    adapter.calls = 0

    recovered = safety.recover_stale(
        tenant_id=TENANT,
        now=NOW + timedelta(seconds=40),
        stale_after=timedelta(seconds=30),
    )

    assert recovered[0].plan_status == "completed"
    assert recovered[0].loop_status is ReactLoopStatus.COMPLETED
    assert adapter.calls == 0
    with factory() as session:
        block = session.get(TrustedToolCallRow, str(block_id))
        assert block.status == "succeeded"
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionAttemptRow)
                .where(ToolExecutionAttemptRow.tool_call_id == str(block_id))
            )
            == 1
        )
