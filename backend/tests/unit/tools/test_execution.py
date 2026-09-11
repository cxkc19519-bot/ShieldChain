from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import TrustedToolCall, TrustedToolCallStatus, TrustedToolRequest
from shieldchain.tools.execution import (
    ExecutionLeaseGrant,
    RecoveryDisposition,
    ToolExecutionLease,
    TrustedToolRecoveryService,
)
from shieldchain.tools.registry import default_tool_registry

NOW = datetime(2026, 7, 23, 11, tzinfo=UTC)
CASE, RUN, PLAN, CALL, EVIDENCE, HOLDER, LEASE = (UUID(int=value) for value in range(1501, 1508))
TOKEN = "a" * 43


def bound(tool="query_firewall_state"):
    query = tool == "query_firewall_state"
    request = TrustedToolRequest(
        CALL,
        CASE,
        RUN,
        PLAN,
        "phase5:execution:1501",
        AgentRole.RESPONSE_PLANNING,
        tool,
        "1",
        {"target_ip": "203.0.113.8"}
        if query
        else {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Reverse exact change.",
        (EvidenceReference(EVIDENCE, CASE, "siem:lease", NOW, "a" * 64),),
        NOW,
    )
    return default_tool_registry().bind(request)


def call(tool="query_firewall_state", status=TrustedToolCallStatus.EXECUTING):
    return TrustedToolCall(bound(tool).request, status, 3, None, NOW)


def lease(*, expires=NOW - timedelta(seconds=1), released=False):
    return ToolExecutionLease(
        LEASE,
        CALL,
        HOLDER,
        1,
        hashlib.sha256(TOKEN.encode("ascii")).hexdigest(),
        NOW - timedelta(minutes=1),
        expires,
        NOW - timedelta(seconds=2) if released else None,
        "completed" if released else None,
    )


def test_lease_grant_binds_ephemeral_token_to_stored_digest() -> None:
    value = lease(expires=NOW + timedelta(seconds=1))
    assert ExecutionLeaseGrant(value, TOKEN).token == TOKEN
    assert value.matches("b" * 43) is False
    with pytest.raises(ValueError, match="does not match"):
        ExecutionLeaseGrant(value, "b" * 43)


def test_expired_read_only_lease_can_retry_within_registered_limit() -> None:
    decision = TrustedToolRecoveryService().decide(
        bound=bound(),
        call=call(),
        lease=lease(),
        attempt_count=2,
        automation_enabled=True,
        budget_remaining=1,
        now=NOW,
    )
    assert decision.disposition is RecoveryDisposition.RETRY_SAFE


def test_state_changing_expiry_requires_status_query_not_replay() -> None:
    decision = TrustedToolRecoveryService().decide(
        bound=bound("block_ip"),
        call=call("block_ip"),
        lease=lease(),
        attempt_count=1,
        automation_enabled=True,
        budget_remaining=1,
        now=NOW,
    )
    assert decision.disposition is RecoveryDisposition.QUERY_STATUS


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"automation_enabled": False}, "automation_disabled"),
        ({"budget_remaining": 0}, "budget_exhausted"),
        ({"attempt_count": 3}, "retry_limit_exhausted"),
        ({"lease": lease(released=True)}, "state_not_recoverable"),
        ({"lease": lease(expires=NOW + timedelta(seconds=1))}, "state_not_recoverable"),
    ],
)
def test_recovery_fails_closed(changes, reason) -> None:
    values = dict(
        bound=bound(),
        call=call(),
        lease=lease(),
        attempt_count=1,
        automation_enabled=True,
        budget_remaining=1,
        now=NOW,
    )
    values.update(changes)
    decision = TrustedToolRecoveryService().decide(**values)
    assert decision.disposition is RecoveryDisposition.MANUAL_REVIEW
    assert decision.reason == reason


def test_waiting_approval_and_verifying_have_distinct_recovery_paths() -> None:
    service = TrustedToolRecoveryService()
    waiting = service.decide(
        bound=bound(),
        call=call(status=TrustedToolCallStatus.AWAITING_APPROVAL),
        lease=None,
        attempt_count=0,
        automation_enabled=True,
        budget_remaining=1,
        now=NOW,
    )
    verifying = service.decide(
        bound=bound(),
        call=call(status=TrustedToolCallStatus.VERIFYING),
        lease=None,
        attempt_count=1,
        automation_enabled=True,
        budget_remaining=1,
        now=NOW,
    )
    assert waiting.disposition is RecoveryDisposition.WAIT_FOR_APPROVAL
    assert verifying.disposition is RecoveryDisposition.VERIFY_RESULT
