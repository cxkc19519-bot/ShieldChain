from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.db.base import Base
from shieldchain.incidents.persistence import (
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.tools.control import TrustedToolControlService
from shieldchain.tools.control_store import SqlAlchemyToolControlStore, StaleAutomationControl
from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolExecutionAttempt,
    ToolRisk,
    ToolTargetType,
    ToolVerification,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)
from shieldchain.tools.execution_store import (
    ExecutionLeaseConflict,
    ExecutionLeaseNotFound,
    SqlAlchemyExecutionStore,
)
from shieldchain.tools.gateway import TrustedToolGateway
from shieldchain.tools.gateway_store import SqlAlchemyGatewayStore
from shieldchain.tools.persistence import (
    ToolApprovalRow,
    ToolAutomationControlRow,
    ToolControlEventRow,
    ToolExecutionAttemptRow,
    ToolExecutionLeaseRow,
    ToolPolicyDecisionRow,
    ToolVerificationRow,
)
from shieldchain.tools.policy import ToolExecutionMode, ToolPolicyContext
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.repositories import (
    SqlAlchemyTrustedToolRepository,
    StaleTrustedToolCall,
    TrustedToolCallNotFound,
    TrustedToolIdempotencyConflict,
)
from shieldchain.tools.simulation import OfflineSimulationAdapter

NOW = datetime(2026, 7, 23, 7, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
OTHER = UUID("00000000-0000-4000-8000-000000000099")
CASE, RUN, SIMULATION, EVIDENCE = (UUID(int=value) for value in range(1101, 1105))
SHA = "c" * 64


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(
            SimulationInstanceRow(
                id=str(SIMULATION),
                scenario_key="tools",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        value.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="INC-TOOLS",
                simulation_instance_id=str(SIMULATION),
                alert_id="ALT",
                alert_status="open",
                endpoint="host",
                username="user",
                source_ip="10.0.0.1",
                remote_ip="203.0.113.8",
                remote_port=443,
                process_name="p",
                parent_process_name="pp",
                command_summary="cmd",
                threat_label="phishing",
                created_at=NOW,
            )
        )
        value.flush()
        value.add(
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
        value.flush()
        value.add(
            EvidenceRecordRow(
                id=str(EVIDENCE),
                run_id=str(RUN),
                evidence_type="network",
                source="siem",
                observed_at=NOW,
                summary="confirmed target",
                raw_reference="siem:1",
                integrity_sha256=SHA,
                confidence=1.0,
                confirmed=True,
                payload_json={},
                created_at=NOW,
            )
        )
        value.commit()
        yield value
    engine.dispose()


def bound(*, target="203.0.113.8"):
    reference = EvidenceReference(EVIDENCE, CASE, "siem:1", NOW, SHA)
    request = TrustedToolRequest(
        UUID(int=1105),
        CASE,
        RUN,
        UUID(int=1106),
        "phase5:block:1105",
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": target, "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Remove exact rule after review.",
        (reference,),
        NOW,
    )
    return default_tool_registry().bind(request)


def test_create_is_tenant_bound_idempotent_and_detects_digest_conflict(session: Session) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    created, is_new = repo.create_or_get(
        session, tenant_id=TENANT, bound=bound(), request_id="req-1"
    )
    session.commit()
    existing, is_new_again = repo.create_or_get(
        session, tenant_id=TENANT, bound=bound(), request_id="req-2"
    )
    assert is_new is True and is_new_again is False
    assert existing == created
    with pytest.raises(TrustedToolIdempotencyConflict):
        repo.create_or_get(
            session, tenant_id=TENANT, bound=bound(target="203.0.113.9"), request_id="req-3"
        )
    assert repo.get(session, tenant_id=OTHER, tool_call_id=created.request.id) is None


def test_cas_transition_rejects_stale_revision_and_cross_tenant(session: Session) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    current, _ = repo.create_or_get(session, tenant_id=TENANT, bound=bound(), request_id="req")
    changed = repo.transition(
        session,
        tenant_id=TENANT,
        current=current,
        target=TrustedToolCallStatus.POLICY_CHECKED,
        now=NOW,
        request_id="req",
    )
    with pytest.raises(StaleTrustedToolCall):
        repo.transition(
            session,
            tenant_id=TENANT,
            current=current,
            target=TrustedToolCallStatus.POLICY_CHECKED,
            now=NOW,
            request_id="req",
        )
    assert changed.revision == 1
    with pytest.raises(TrustedToolCallNotFound):
        repo.append_policy(
            session,
            tenant_id=OTHER,
            decision=PolicyDecision(
                current.request.id,
                PolicyOutcome.DENY,
                PolicyReason.CALLER_NOT_ALLOWED,
                "v1",
                ToolRisk.HIGH,
                NOW,
                NOW + timedelta(minutes=1),
            ),
        )


def test_policy_approval_attempt_and_verification_are_append_only(session: Session) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    call, _ = repo.create_or_get(session, tenant_id=TENANT, bound=bound(), request_id="req")
    policy = PolicyDecision(
        call.request.id,
        PolicyOutcome.APPROVAL_REQUIRED,
        PolicyReason.APPROVAL_REQUIRED,
        "v1",
        ToolRisk.HIGH,
        NOW,
        NOW + timedelta(minutes=5),
    )
    approval = ApprovalDecision(
        uuid4(),
        call.request.id,
        call.request.request_digest,
        ApprovalOutcome.APPROVED,
        uuid4(),
        "v1",
        "Approved fixed target",
        NOW,
        NOW + timedelta(minutes=2),
    )
    attempt = ToolExecutionAttempt(
        uuid4(),
        call.request.id,
        1,
        ExecutionOutcome.SUCCEEDED,
        "Firewall rule applied",
        None,
        NOW,
        NOW,
    )
    verification = ToolVerification(
        uuid4(),
        call.request.id,
        VerificationOutcome.VERIFIED,
        {"firewall_status": "blocked"},
        call.request.evidence,
        None,
        NOW,
    )
    repo.append_policy(session, tenant_id=TENANT, decision=policy)
    repo.append_approval(session, tenant_id=TENANT, decision=approval)
    repo.append_attempt(session, tenant_id=TENANT, attempt=attempt)
    repo.append_verification(session, tenant_id=TENANT, verification=verification)
    session.flush()
    for row_type in (
        ToolPolicyDecisionRow,
        ToolApprovalRow,
        ToolExecutionAttemptRow,
        ToolVerificationRow,
    ):
        assert session.scalar(select(func.count()).select_from(row_type)) == 1


def test_gateway_store_rolls_back_attempt_and_transition_together(session: Session) -> None:
    store = SqlAlchemyGatewayStore(session)
    call, _ = store.create_or_get(tenant_id=TENANT, bound=bound(), request_id="req-atomic-create")
    with store.atomic():
        call = store.transition(
            tenant_id=TENANT,
            current=call,
            target=TrustedToolCallStatus.POLICY_CHECKED,
            now=NOW,
            request_id="req-atomic-policy",
        )
        call = store.transition(
            tenant_id=TENANT,
            current=call,
            target=TrustedToolCallStatus.APPROVED,
            now=NOW,
            request_id="req-atomic-approved",
        )
    with store.atomic():
        call = store.transition(
            tenant_id=TENANT,
            current=call,
            target=TrustedToolCallStatus.EXECUTING,
            now=NOW,
            request_id="req-atomic-executing",
        )
    attempt = ToolExecutionAttempt(
        uuid4(),
        call.request.id,
        1,
        ExecutionOutcome.FAILED,
        "Sanitized failure",
        "tool_failure",
        NOW,
        NOW,
    )
    with pytest.raises(RuntimeError, match="force rollback"):
        with store.atomic():
            store.append_attempt(tenant_id=TENANT, attempt=attempt)
            store.transition(
                tenant_id=TENANT,
                current=call,
                target=TrustedToolCallStatus.FAILED,
                now=NOW,
                request_id="req-atomic-result",
            )
            raise RuntimeError("force rollback")
    assert session.scalar(select(func.count()).select_from(ToolExecutionAttemptRow)) == 0
    stored = SqlAlchemyTrustedToolRepository().get(
        session, tenant_id=TENANT, tool_call_id=call.request.id
    )
    assert stored and stored.status is TrustedToolCallStatus.EXECUTING


def test_execution_lease_is_cas_bound_tenant_scoped_and_token_hashed(
    session: Session,
) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    execution = SqlAlchemyExecutionStore(session)
    call, _ = repo.create_or_get(
        session, tenant_id=TENANT, bound=bound(), request_id="req-lease-create"
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.POLICY_CHECKED,
        now=NOW,
        request_id="req-lease-policy",
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.APPROVED,
        now=NOW,
        request_id="req-lease-approved",
    )
    grant = execution.acquire_lease(
        tenant_id=TENANT,
        call=call,
        holder_id=uuid4(),
        now=NOW,
        duration=timedelta(seconds=10),
        request_id="req-lease-acquire",
    )
    row = session.get(ToolExecutionLeaseRow, str(grant.lease.id))
    assert row and row.token_digest != grant.token
    assert grant.lease.matches(grant.token)
    with pytest.raises(ExecutionLeaseConflict, match="already active"):
        execution.acquire_lease(
            tenant_id=TENANT,
            call=call,
            holder_id=uuid4(),
            now=NOW,
            duration=timedelta(seconds=10),
            request_id="req-lease-duplicate",
        )
    with pytest.raises(ExecutionLeaseNotFound):
        execution.release_lease(
            tenant_id=OTHER,
            call=call,
            grant=grant,
            now=NOW,
            reason="completed",
            request_id="req-lease-cross-tenant",
        )
    released = execution.release_lease(
        tenant_id=TENANT,
        call=call,
        grant=grant,
        now=NOW,
        reason="completed",
        request_id="req-lease-release",
    )
    assert released.active is False


def test_usage_and_expired_lease_scan_are_server_counted(session: Session) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    execution = SqlAlchemyExecutionStore(session)
    call, _ = repo.create_or_get(
        session, tenant_id=TENANT, bound=bound(), request_id="req-usage-create"
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.POLICY_CHECKED,
        now=NOW,
        request_id="req-usage-policy",
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.APPROVED,
        now=NOW,
        request_id="req-usage-approved",
    )
    grant = execution.acquire_lease(
        tenant_id=TENANT,
        call=call,
        holder_id=uuid4(),
        now=NOW,
        duration=timedelta(seconds=1),
        request_id="req-usage-lease",
    )
    repo.append_attempt(
        session,
        tenant_id=TENANT,
        attempt=ToolExecutionAttempt(
            uuid4(),
            call.request.id,
            1,
            ExecutionOutcome.UNKNOWN,
            "Outcome unknown",
            "timeout",
            NOW,
            NOW,
        ),
    )
    session.flush()
    usage = execution.usage(tenant_id=TENANT, run_id=RUN)
    assert (usage.call_count, usage.attempt_count) == (1, 1)
    assert execution.usage(tenant_id=OTHER, run_id=RUN).call_count == 0
    assert execution.expired_leases(tenant_id=TENANT, now=NOW + timedelta(seconds=2)) == (
        grant.lease,
    )
    assert execution.expired_leases(tenant_id=OTHER, now=NOW + timedelta(seconds=2)) == ()


def test_offline_simulation_runs_through_policy_lease_and_verification(
    session: Session,
) -> None:
    registry = default_tool_registry()
    request = bound()
    context = ToolPolicyContext(
        tenant_id=TENANT,
        principal_id=UUID(int=1199),
        case_id=CASE,
        run_id=RUN,
        role=AgentRole.RESPONSE_PLANNING,
        mode=ToolExecutionMode.SIMULATION,
        automation_enabled=True,
        emergency_stop_active=False,
        allowed_tools=frozenset(item.definition.identity for item in registry.registrations),
        allowed_targets={ToolTargetType.IPV4: frozenset({"203.0.113.8"})},
        confirmed_evidence_ids=frozenset({EVIDENCE}),
        tool_calls_used=0,
        tool_call_limit=5,
        calls_in_window=0,
        rate_limit=3,
        simulation_auto_approve_critical=False,
        now=NOW,
    )
    adapter = OfflineSimulationAdapter(
        initialized_at=NOW,
        firewall_targets=frozenset({"203.0.113.8"}),
        endpoint_targets=frozenset({"endpoint-42"}),
        account_targets=frozenset({"user-42"}),
    )
    result = TrustedToolGateway().submit(
        bound=request,
        context=context,
        store=SqlAlchemyGatewayStore(session),
        adapter=adapter,
        request_id="req-offline-simulation-gateway",
    )
    session.flush()
    assert result.call.status is TrustedToolCallStatus.SUCCEEDED
    assert result.attempt and result.attempt.outcome is ExecutionOutcome.SUCCEEDED
    assert result.verification
    assert result.verification.outcome is VerificationOutcome.VERIFIED
    assert session.scalar(select(func.count()).select_from(ToolExecutionAttemptRow)) == 1
    assert session.scalar(select(func.count()).select_from(ToolExecutionLeaseRow)) == 1
    assert session.scalar(select(func.count()).select_from(ToolVerificationRow)) == 1


def test_control_store_persists_pause_resume_global_cas_and_lease_block(
    session: Session,
) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    store = SqlAlchemyToolControlStore(session, repo)
    service = TrustedToolControlService()
    call, _ = repo.create_or_get(
        session, tenant_id=TENANT, bound=bound(), request_id="req-control-create"
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.POLICY_CHECKED,
        now=NOW,
        request_id="req-control-policy",
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.APPROVED,
        now=NOW,
        request_id="req-control-approved",
    )
    with session.begin_nested():
        paused = service.pause(
            tenant_id=TENANT,
            call=call,
            actor_subject_id=UUID(int=1198),
            reason="operator review",
            now=NOW,
            request_id="req-control-pause",
            store=store,
        )
    with session.begin_nested():
        resumed = service.resume(
            tenant_id=TENANT,
            call=paused,
            actor_subject_id=UUID(int=1198),
            reason="review complete",
            now=NOW,
            request_id="req-control-resume",
            store=store,
        )
    with session.begin_nested():
        disabled = service.set_global(
            tenant_id=TENANT,
            actor_subject_id=UUID(int=1198),
            automation_enabled=False,
            emergency_stop_active=False,
            reason="maintenance",
            now=NOW,
            store=store,
        )
    assert resumed.status is TrustedToolCallStatus.APPROVED
    assert session.scalar(select(func.count()).select_from(ToolControlEventRow)) == 3
    assert session.scalar(select(func.count()).select_from(ToolAutomationControlRow)) == 1
    with pytest.raises(ExecutionLeaseConflict, match="control blocks"):
        SqlAlchemyExecutionStore(session).acquire_lease(
            tenant_id=TENANT,
            call=resumed,
            holder_id=uuid4(),
            now=NOW,
            duration=timedelta(seconds=10),
            request_id="req-control-blocked-lease",
        )
    stale = disabled
    current = service.set_global(
        tenant_id=TENANT,
        actor_subject_id=UUID(int=1198),
        automation_enabled=True,
        emergency_stop_active=False,
        reason="maintenance complete",
        now=NOW,
        store=store,
    )
    with pytest.raises(StaleAutomationControl):
        store.set_control(current=stale, changed=current)


def test_emergency_stop_leaves_dispatched_call_executing(session: Session) -> None:
    repo = SqlAlchemyTrustedToolRepository()
    call, _ = repo.create_or_get(
        session, tenant_id=TENANT, bound=bound(), request_id="req-stop-create"
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.POLICY_CHECKED,
        now=NOW,
        request_id="req-stop-policy",
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.APPROVED,
        now=NOW,
        request_id="req-stop-approved",
    )
    call = repo.transition(
        session,
        tenant_id=TENANT,
        current=call,
        target=TrustedToolCallStatus.EXECUTING,
        now=NOW,
        request_id="req-stop-executing",
    )
    store = SqlAlchemyToolControlStore(session, repo)
    TrustedToolControlService().set_global(
        tenant_id=TENANT,
        actor_subject_id=UUID(int=1198),
        automation_enabled=False,
        emergency_stop_active=True,
        reason="emergency",
        now=NOW,
        store=store,
    )
    stored = repo.get(session, tenant_id=TENANT, tool_call_id=call.request.id)
    assert stored and stored.status is TrustedToolCallStatus.EXECUTING
