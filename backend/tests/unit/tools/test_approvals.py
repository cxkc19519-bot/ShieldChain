from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.approvals import (
    AUTOMATIC_POLICY_SUBJECT,
    ApprovalAccessDenied,
    ApprovalAuthority,
    ApprovalConflict,
    ApprovalExpired,
    ApprovalStateInvalid,
    TrustedToolApprovalService,
)
from shieldchain.tools.domain import (
    ApprovalOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolRisk,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
)

NOW = datetime(2026, 7, 23, 9, tzinfo=UTC)
TENANT, REQUESTER, APPROVER, CASE, RUN, PLAN, CALL, EVIDENCE = (
    UUID(int=value) for value in range(1301, 1309)
)
REF = EvidenceReference(EVIDENCE, CASE, "siem:1", NOW, "e" * 64)


class Store:
    def __init__(self):
        self.items = {}

    def latest(self, *, tenant_id, request_id):
        return self.items.get((tenant_id, request_id))

    def append(self, *, tenant_id, decision):
        self.items[(tenant_id, decision.request_id)] = decision


def call(status=TrustedToolCallStatus.AWAITING_APPROVAL, *, target="203.0.113.8"):
    request = TrustedToolRequest(
        CALL,
        CASE,
        RUN,
        PLAN,
        "phase5:approval:1301",
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": target, "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Reverse exact rule.",
        (REF,),
        NOW,
    )
    return TrustedToolCall(request, status, 2, PolicyReason.APPROVAL_REQUIRED, NOW)


def policy(
    *,
    risk=ToolRisk.HIGH,
    outcome=PolicyOutcome.APPROVAL_REQUIRED,
    reason=PolicyReason.APPROVAL_REQUIRED,
    expires=None,
):
    return PolicyDecision(
        CALL, outcome, reason, "v1", risk, NOW, expires or NOW + timedelta(minutes=5)
    )


def authority(*, subject=APPROVER, permissions=frozenset({"trusted_tools.approve"}), now=NOW):
    return ApprovalAuthority(TENANT, subject, permissions, now)


def test_high_risk_approval_is_digest_bound_append_only_and_idempotent() -> None:
    store = Store()
    service = TrustedToolApprovalService()
    first = service.decide(
        call=call(),
        policy=policy(),
        authority=authority(),
        requester_subject_id=REQUESTER,
        outcome=ApprovalOutcome.APPROVED,
        reason_summary="Approved fixed simulation target.",
        store=store,
    )
    second = service.decide(
        call=call(),
        policy=policy(),
        authority=authority(),
        requester_subject_id=REQUESTER,
        outcome=ApprovalOutcome.APPROVED,
        reason_summary="Repeated request.",
        store=store,
    )
    assert first is second
    assert first.request_digest == call().request.request_digest
    with pytest.raises(ApprovalConflict):
        service.decide(
            call=call(),
            policy=policy(),
            authority=authority(),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.REJECTED,
            reason_summary="Conflicting decision.",
            store=store,
        )


def test_requester_cannot_self_approve_and_missing_permission_is_denied() -> None:
    service = TrustedToolApprovalService()
    with pytest.raises(ApprovalAccessDenied, match="requester"):
        service.decide(
            call=call(),
            policy=policy(),
            authority=authority(subject=REQUESTER),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="self",
            store=Store(),
        )
    with pytest.raises(ApprovalAccessDenied, match="permission"):
        service.decide(
            call=call(),
            policy=policy(),
            authority=authority(permissions=frozenset()),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="missing role",
            store=Store(),
        )


def test_critical_requires_distinct_critical_permission() -> None:
    service = TrustedToolApprovalService()
    with pytest.raises(ApprovalAccessDenied):
        service.decide(
            call=call(),
            policy=policy(risk=ToolRisk.CRITICAL),
            authority=authority(),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="not enough",
            store=Store(),
        )
    decision = service.decide(
        call=call(),
        policy=policy(risk=ToolRisk.CRITICAL),
        authority=authority(permissions=frozenset({"trusted_tools.approve_critical"})),
        requester_subject_id=REQUESTER,
        outcome=ApprovalOutcome.APPROVED,
        reason_summary="critical approval",
        store=Store(),
    )
    assert decision.outcome is ApprovalOutcome.APPROVED


def test_expired_policy_wrong_state_and_nonapproval_policy_fail_closed() -> None:
    service = TrustedToolApprovalService()
    with pytest.raises(ApprovalExpired):
        service.decide(
            call=call(),
            policy=policy(expires=NOW + timedelta(seconds=1)),
            authority=authority(now=NOW + timedelta(seconds=1)),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="late",
            store=Store(),
        )
    with pytest.raises(ApprovalStateInvalid, match="state"):
        service.decide(
            call=call(TrustedToolCallStatus.EXECUTING),
            policy=policy(),
            authority=authority(),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="too late",
            store=Store(),
        )
    with pytest.raises(ApprovalStateInvalid, match="does not require"):
        service.decide(
            call=call(),
            policy=policy(outcome=PolicyOutcome.ALLOW, reason=PolicyReason.POLICY_ALLOWED),
            authority=authority(),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="not needed",
            store=Store(),
        )


def test_automatic_simulation_approval_is_explicitly_recorded() -> None:
    store = Store()
    decision = TrustedToolApprovalService().record_automatic(
        tenant_id=TENANT,
        call=call(TrustedToolCallStatus.POLICY_CHECKED),
        policy=policy(
            outcome=PolicyOutcome.ALLOW, reason=PolicyReason.AUTOMATIC_SIMULATION_APPROVAL
        ),
        store=store,
    )
    assert decision.approver_subject_id == AUTOMATIC_POLICY_SUBJECT
    assert decision.outcome is ApprovalOutcome.APPROVED


def test_parameter_change_invalidates_existing_digest() -> None:
    store = Store()
    service = TrustedToolApprovalService()
    service.decide(
        call=call(),
        policy=policy(),
        authority=authority(),
        requester_subject_id=REQUESTER,
        outcome=ApprovalOutcome.APPROVED,
        reason_summary="original",
        store=store,
    )
    with pytest.raises(ApprovalConflict):
        service.decide(
            call=call(target="203.0.113.9"),
            policy=policy(),
            authority=authority(),
            requester_subject_id=REQUESTER,
            outcome=ApprovalOutcome.APPROVED,
            reason_summary="changed",
            store=store,
        )
