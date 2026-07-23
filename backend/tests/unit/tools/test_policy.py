from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import PolicyOutcome, PolicyReason, ToolTargetType, TrustedToolRequest
from shieldchain.tools.policy import DeterministicToolPolicy, ToolExecutionMode, ToolPolicyContext
from shieldchain.tools.registry import default_tool_registry

NOW = datetime(2026, 7, 23, 8, tzinfo=UTC)
TENANT, PRINCIPAL, CASE, RUN, PLAN, CALL, EVIDENCE = (
    UUID(int=value) for value in range(1201, 1208)
)
REF = EvidenceReference(EVIDENCE, CASE, "siem:1", NOW, "d" * 64)


def bound(tool="block_ip"):
    if tool == "disable_account":
        arguments = {"account_id": "user-42", "reason_code": "credential_abuse"}
        expected = {"account_status": "disabled"}
    elif tool == "query_firewall_state":
        arguments = {"target_ip": "203.0.113.8"}
        expected = {"firewall_status": "blocked"}
    else:
        arguments = {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600}
        expected = {"firewall_status": "blocked"}
    return default_tool_registry().bind(
        TrustedToolRequest(
            CALL,
            CASE,
            RUN,
            PLAN,
            "phase5:policy:1201",
            AgentRole.RESPONSE_PLANNING,
            tool,
            "1",
            arguments,
            expected,
            "Reverse exact scoped change.",
            (REF,),
            NOW,
        )
    )


def context(**changes):
    values = dict(
        tenant_id=TENANT,
        principal_id=PRINCIPAL,
        case_id=CASE,
        run_id=RUN,
        role=AgentRole.RESPONSE_PLANNING,
        mode=ToolExecutionMode.SIMULATION,
        automation_enabled=True,
        emergency_stop_active=False,
        allowed_tools=frozenset(
            {item.definition.identity for item in default_tool_registry().registrations}
        ),
        allowed_targets={
            ToolTargetType.IPV4: frozenset({"203.0.113.8"}),
            ToolTargetType.ACCOUNT: frozenset({"user-42"}),
        },
        confirmed_evidence_ids=frozenset({EVIDENCE}),
        tool_calls_used=0,
        tool_call_limit=5,
        calls_in_window=0,
        rate_limit=3,
        simulation_auto_approve_critical=False,
        now=NOW,
    )
    values.update(changes)
    return ToolPolicyContext(**values)


def test_simulation_high_risk_is_explicitly_auto_approved_but_real_requires_approval() -> None:
    policy = DeterministicToolPolicy()
    simulated = policy.evaluate(bound(), context())
    real = policy.evaluate(bound(), context(mode=ToolExecutionMode.REAL))
    assert simulated.outcome is PolicyOutcome.ALLOW
    assert simulated.reason is PolicyReason.AUTOMATIC_SIMULATION_APPROVAL
    assert real.outcome is PolicyOutcome.APPROVAL_REQUIRED


def test_critical_simulation_requires_explicit_policy_override() -> None:
    policy = DeterministicToolPolicy()
    denied_auto = policy.evaluate(bound("disable_account"), context())
    allowed_auto = policy.evaluate(
        bound("disable_account"), context(simulation_auto_approve_critical=True)
    )
    assert denied_auto.outcome is PolicyOutcome.APPROVAL_REQUIRED
    assert allowed_auto.reason is PolicyReason.AUTOMATIC_SIMULATION_APPROVAL


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"automation_enabled": False}, PolicyReason.AUTOMATION_DISABLED),
        ({"emergency_stop_active": True}, PolicyReason.EMERGENCY_STOP_ACTIVE),
        ({"allowed_tools": frozenset()}, PolicyReason.TOOL_NOT_ALLOWED),
        ({"role": AgentRole.REPORTING}, PolicyReason.CALLER_NOT_ALLOWED),
        ({"case_id": UUID(int=9999)}, PolicyReason.CASE_BINDING_INVALID),
        ({"confirmed_evidence_ids": frozenset()}, PolicyReason.EVIDENCE_INVALID),
        ({"allowed_targets": {}}, PolicyReason.TARGET_OUT_OF_SCOPE),
        ({"tool_calls_used": 5}, PolicyReason.BUDGET_EXHAUSTED),
        ({"calls_in_window": 3}, PolicyReason.RATE_LIMITED),
    ],
)
def test_default_deny_matrix_has_stable_reasons(changes, reason) -> None:
    decision = DeterministicToolPolicy().evaluate(bound(), context(**changes))
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason is reason


def test_check_order_prioritizes_global_controls_over_tool_details() -> None:
    decision = DeterministicToolPolicy().evaluate(
        bound(),
        context(automation_enabled=False, emergency_stop_active=True, allowed_tools=frozenset()),
    )
    assert decision.reason is PolicyReason.AUTOMATION_DISABLED


def test_read_only_query_is_allowed_after_all_security_checks() -> None:
    decision = DeterministicToolPolicy().evaluate(bound("query_firewall_state"), context())
    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.reason is PolicyReason.POLICY_ALLOWED


def test_context_defensively_freezes_authority_sets() -> None:
    targets = {ToolTargetType.IPV4: {"203.0.113.8"}}
    value = context(allowed_targets=targets)
    targets[ToolTargetType.IPV4].add("198.51.100.2")
    assert "198.51.100.2" not in value.allowed_targets[ToolTargetType.IPV4]
