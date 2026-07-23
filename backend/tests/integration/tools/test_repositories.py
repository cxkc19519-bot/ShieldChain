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
from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolExecutionAttempt,
    ToolRisk,
    ToolVerification,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)
from shieldchain.tools.gateway_store import SqlAlchemyGatewayStore
from shieldchain.tools.persistence import (
    ToolApprovalRow,
    ToolExecutionAttemptRow,
    ToolPolicyDecisionRow,
    ToolVerificationRow,
)
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.repositories import (
    SqlAlchemyTrustedToolRepository,
    StaleTrustedToolCall,
    TrustedToolCallNotFound,
    TrustedToolIdempotencyConflict,
)

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
