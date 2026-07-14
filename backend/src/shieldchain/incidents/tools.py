from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from ipaddress import IPv4Address

from shieldchain.incidents.domain import (
    BlockOutcome,
    PhishingScenarioState,
    ToolCallStatus,
    ToolResult,
    VerificationResult,
)


class InvalidSimulationTarget(ValueError):
    def __init__(self, target: str) -> None:
        self.target = target
        super().__init__(f"invalid simulation target: {target}")


def _validate_target(state: PhishingScenarioState, ip: IPv4Address) -> None:
    if ip != state.remote_ip:
        raise InvalidSimulationTarget(str(ip))


def _state_view(state: PhishingScenarioState) -> dict[str, str]:
    return {
        "firewall_status": state.firewall_status,
        "connection_status": state.connection_status,
    }


def _result(
    state: PhishingScenarioState,
    ip: IPv4Address,
    idempotency_key: str,
    status: ToolCallStatus,
    before_state: dict[str, str],
    *,
    error_code: str | None = None,
) -> ToolResult:
    return ToolResult(
        status=status,
        tool_name="block_ip",
        target=str(ip),
        idempotency_key=idempotency_key,
        before_state=before_state,
        after_state=_state_view(state),
        error_code=error_code,
    )


class SimulatedFirewall:
    def block_ip(
        self,
        state: PhishingScenarioState,
        ip: IPv4Address,
        idempotency_key: str,
        *,
        fail_once: bool = False,
    ) -> BlockOutcome:
        _validate_target(state, ip)
        before_state = _state_view(state)
        if fail_once and not state.fail_block_consumed:
            consumed = replace(state, fail_block_consumed=True)
            return BlockOutcome(
                state=consumed,
                result=_result(
                    consumed,
                    ip,
                    idempotency_key,
                    ToolCallStatus.FAILED,
                    before_state,
                    error_code="simulated_block_failure",
                ),
            )
        if state.firewall_status == "blocked":
            return BlockOutcome(
                state=state,
                result=_result(
                    state,
                    ip,
                    idempotency_key,
                    ToolCallStatus.ALREADY_BLOCKED,
                    before_state,
                ),
            )
        blocked = replace(state, connection_status="blocked", firewall_status="blocked")
        return BlockOutcome(
            state=blocked,
            result=_result(
                blocked,
                ip,
                idempotency_key,
                ToolCallStatus.BLOCKED,
                before_state,
            ),
        )


def verify_block(
    state: PhishingScenarioState, ip: IPv4Address, now: datetime
) -> VerificationResult:
    _validate_target(state, ip)
    return VerificationResult(
        blocked=state.firewall_status == "blocked",
        connection_stopped=state.connection_status == "blocked",
        observed_at=now,
        evidence_ids=(),
    )
