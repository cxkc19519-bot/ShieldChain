from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import (
    ExecutionOutcome,
    TrustedToolRequest,
    VerificationOutcome,
)
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.simulation import OfflineSimulationAdapter, SimulationTargetRejected

NOW = datetime(2026, 7, 23, 12, tzinfo=UTC)
CASE, RUN, PLAN, EVIDENCE = (UUID(int=value) for value in range(1601, 1605))
REF = EvidenceReference(EVIDENCE, CASE, "simulation:fixed", NOW, "b" * 64)


def adapter(**changes):
    values = dict(
        initialized_at=NOW,
        firewall_targets=frozenset({"203.0.113.8"}),
        endpoint_targets=frozenset({"endpoint-42"}),
        account_targets=frozenset({"user-42"}),
    )
    values.update(changes)
    return OfflineSimulationAdapter(**values)


def bound(tool: str, *, expected: str | None = None, target: str | None = None):
    if "firewall" in tool or tool == "block_ip":
        arguments = {"target_ip": target or "203.0.113.8"}
        if tool == "block_ip":
            arguments["rule_ttl_seconds"] = 3600
        expected_state = {"firewall_status": expected or "blocked"}
    elif "endpoint" in tool or tool == "isolate_endpoint":
        arguments = {"endpoint_id": target or "endpoint-42"}
        if tool == "isolate_endpoint":
            arguments["reason_code"] = "confirmed_compromise"
        expected_state = {"isolation_status": expected or "isolated"}
    else:
        arguments = {"account_id": target or "user-42"}
        if tool == "disable_account":
            arguments["reason_code"] = "credential_abuse"
        expected_state = {"account_status": expected or "disabled"}
    return default_tool_registry().bind(
        TrustedToolRequest(
            uuid4(),
            CASE,
            RUN,
            PLAN,
            f"phase5:simulation:{tool}:1601",
            AgentRole.RESPONSE_PLANNING,
            tool,
            "1",
            arguments,
            expected_state,
            "Restore the exact prior simulation state.",
            (REF,),
            NOW,
        )
    )


@pytest.mark.parametrize(
    ("change", "query", "state_key", "state_value"),
    [
        ("block_ip", "query_firewall_state", "firewall_status", "blocked"),
        ("isolate_endpoint", "query_endpoint_state", "isolation_status", "isolated"),
        ("disable_account", "query_account_state", "account_status", "disabled"),
    ],
)
def test_each_change_has_read_only_query_and_post_execution_verification(
    change, query, state_key, state_value
) -> None:
    simulation = adapter()
    change_request = bound(change)
    execution = simulation.execute(change_request)
    verification = simulation.verify(change_request, execution, now=NOW)
    query_request = bound(query, expected=state_value)
    query_execution = simulation.execute(query_request)
    query_verification = simulation.verify(query_request, query_execution, now=NOW)
    assert execution.outcome is ExecutionOutcome.SUCCEEDED
    assert verification.outcome is VerificationOutcome.VERIFIED
    assert query_execution.outcome is ExecutionOutcome.SUCCEEDED
    assert query_verification.observed_state == {state_key: state_value}
    assert query_verification.outcome is VerificationOutcome.VERIFIED


def test_verification_fails_when_observed_state_does_not_match_expected() -> None:
    simulation = adapter()
    request = bound("query_endpoint_state", expected="isolated")
    execution = simulation.execute(request)
    verification = simulation.verify(request, execution, now=NOW)
    assert verification.outcome is VerificationOutcome.FAILED
    assert verification.observed_state == {"isolation_status": "connected"}


@pytest.mark.parametrize(
    ("tool", "target"),
    [
        ("block_ip", "203.0.113.9"),
        ("isolate_endpoint", "endpoint-99"),
        ("disable_account", "user-99"),
    ],
)
def test_unknown_targets_are_rejected_without_dynamic_creation(tool, target) -> None:
    with pytest.raises(SimulationTargetRejected, match="allowlist"):
        adapter().execute(bound(tool, target=target))


@pytest.mark.parametrize(
    ("tool", "error_category"),
    [
        ("block_ip", "simulated_block_failure"),
        ("isolate_endpoint", "simulated_endpoint_failure"),
        ("disable_account", "simulated_account_failure"),
    ],
)
def test_fixed_fail_once_path_does_not_report_success(tool, error_category) -> None:
    simulation = adapter(fail_once_tools=frozenset({tool}))
    first = simulation.execute(bound(tool))
    second = simulation.execute(bound(tool))
    assert first.outcome is ExecutionOutcome.FAILED
    assert first.error_category == error_category
    assert second.outcome is ExecutionOutcome.SUCCEEDED


def test_adapter_output_is_fixed_summary_without_target_or_private_input() -> None:
    result = adapter().execute(bound("query_account_state"))
    assert result.result_summary == "Account state query completed."
    assert "user-42" not in result.result_summary
