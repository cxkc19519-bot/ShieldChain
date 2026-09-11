from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

from shieldchain.incidents.domain import ToolCallStatus
from shieldchain.incidents.scenario import seed_phishing_scenario
from shieldchain.incidents.tools import InvalidSimulationTarget, SimulatedFirewall, verify_block

NOW = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)


def test_normal_block_returns_new_blocked_snapshot_and_exact_state_views() -> None:
    state = seed_phishing_scenario(NOW)
    outcome = SimulatedFirewall().block_ip(state, state.remote_ip, "key-1")

    assert outcome.result.status is ToolCallStatus.BLOCKED
    assert outcome.result.tool_name == "block_ip"
    assert outcome.result.target == "198.51.100.24"
    assert outcome.result.idempotency_key == "key-1"
    assert outcome.result.before_state == {
        "firewall_status": "not_blocked",
        "connection_status": "active",
    }
    assert outcome.result.after_state == {
        "firewall_status": "blocked",
        "connection_status": "blocked",
    }
    assert outcome.result.error_code is None
    assert outcome.state.firewall_status == "blocked"
    assert outcome.state.connection_status == "blocked"
    assert state.firewall_status == "not_blocked"
    assert state.connection_status == "active"


def test_new_key_against_blocked_target_returns_already_blocked() -> None:
    state = seed_phishing_scenario(NOW)
    blocked = SimulatedFirewall().block_ip(state, state.remote_ip, "key-1").state
    outcome = SimulatedFirewall().block_ip(blocked, blocked.remote_ip, "key-2")

    assert outcome.result.status is ToolCallStatus.ALREADY_BLOCKED
    assert outcome.state is blocked
    assert outcome.result.before_state == outcome.result.after_state == {
        "firewall_status": "blocked",
        "connection_status": "blocked",
    }


def test_fail_once_does_not_change_firewall_or_connection_and_consumes_failure() -> None:
    state = seed_phishing_scenario(NOW)
    outcome = SimulatedFirewall().block_ip(state, state.remote_ip, "key-1", fail_once=True)

    assert outcome.result.status is ToolCallStatus.FAILED
    assert outcome.result.error_code == "simulated_block_failure"
    assert outcome.state.firewall_status == "not_blocked"
    assert outcome.state.connection_status == "active"
    assert outcome.state.fail_block_consumed is True
    assert outcome.result.before_state == outcome.result.after_state == {
        "firewall_status": "not_blocked",
        "connection_status": "active",
    }


def test_fail_once_succeeds_after_failure_is_consumed() -> None:
    firewall = SimulatedFirewall()
    state = seed_phishing_scenario(NOW)
    failed = firewall.block_ip(state, state.remote_ip, "key-1", fail_once=True)
    outcome = firewall.block_ip(failed.state, state.remote_ip, "key-2", fail_once=True)

    assert outcome.result.status is ToolCallStatus.BLOCKED


def test_wrong_target_raises_before_changing_state() -> None:
    state = seed_phishing_scenario(NOW)
    target = ip_address("198.51.100.25")

    with pytest.raises(InvalidSimulationTarget) as caught:
        SimulatedFirewall().block_ip(state, target, "key-1", fail_once=True)

    assert caught.value.target == "198.51.100.25"
    assert str(caught.value) == "invalid simulation target: 198.51.100.25"
    assert state.fail_block_consumed is False
    assert state.firewall_status == "not_blocked"


def test_verify_block_is_read_only_and_returns_empty_evidence_ids() -> None:
    state = replace(
        seed_phishing_scenario(NOW), firewall_status="blocked", connection_status="blocked"
    )
    original = replace(state)

    result = verify_block(state, state.remote_ip, NOW)

    assert result.blocked is True
    assert result.connection_stopped is True
    assert result.observed_at == NOW
    assert result.evidence_ids == ()
    assert state == original


def test_verify_block_reports_each_state_independently() -> None:
    state = seed_phishing_scenario(NOW)
    result = verify_block(
        replace(state, firewall_status="blocked", connection_status="active"),
        state.remote_ip,
        NOW,
    )
    assert result.blocked is True
    assert result.connection_stopped is False


def test_verify_block_rejects_wrong_target() -> None:
    state = seed_phishing_scenario(NOW)
    with pytest.raises(InvalidSimulationTarget):
        verify_block(state, ip_address("198.51.100.25"), NOW)
