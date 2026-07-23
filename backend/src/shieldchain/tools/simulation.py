"""Deterministic offline adapters for the fixed trusted-tool registry."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from ipaddress import IPv4Address
from threading import RLock
from uuid import uuid4

from shieldchain.incidents.domain import ToolCallStatus
from shieldchain.incidents.scenario import seed_phishing_scenario
from shieldchain.incidents.tools import SimulatedFirewall
from shieldchain.tools.domain import (
    ExecutionOutcome,
    PolicyReason,
    ToolVerification,
    VerificationOutcome,
)
from shieldchain.tools.gateway import AdapterExecution
from shieldchain.tools.registry import BoundToolRequest


class SimulationTargetRejected(ValueError):
    pass


class OfflineSimulationAdapter:
    """In-memory, allowlisted simulation with no network or command access."""

    def __init__(
        self,
        *,
        initialized_at: datetime,
        firewall_targets: frozenset[str],
        endpoint_targets: frozenset[str],
        account_targets: frozenset[str],
        fail_once_tools: frozenset[str] = frozenset(),
    ) -> None:
        self._lock = RLock()
        self._firewall = SimulatedFirewall()
        self._firewalls = {
            target: replace(
                seed_phishing_scenario(initialized_at),
                remote_ip=IPv4Address(target),
                firewall_status="not_blocked",
                connection_status="active",
                fail_block_consumed=False,
            )
            for target in firewall_targets
        }
        self._endpoints = {target: "connected" for target in endpoint_targets}
        self._accounts = {target: "enabled" for target in account_targets}
        self._fail_once = set(fail_once_tools)
        allowed = {
            "query_firewall_state",
            "block_ip",
            "query_endpoint_state",
            "isolate_endpoint",
            "query_account_state",
            "disable_account",
        }
        if not self._fail_once <= allowed:
            raise ValueError("fail_once_tools contains an unknown tool")

    def execute(self, request: BoundToolRequest) -> AdapterExecution:
        name = request.registration.definition.name
        with self._lock:
            if name == "query_firewall_state":
                self._firewall_state(request)
                return AdapterExecution(
                    ExecutionOutcome.SUCCEEDED, "Firewall state query completed."
                )
            if name == "block_ip":
                return self._block_ip(request)
            if name == "query_endpoint_state":
                self._endpoint_state(request)
                return AdapterExecution(
                    ExecutionOutcome.SUCCEEDED, "Endpoint state query completed."
                )
            if name == "isolate_endpoint":
                return self._isolate_endpoint(request)
            if name == "query_account_state":
                self._account_state(request)
                return AdapterExecution(
                    ExecutionOutcome.SUCCEEDED, "Account state query completed."
                )
            if name == "disable_account":
                return self._disable_account(request)
        raise ValueError("tool is not supported by the offline simulation adapter")

    def verify(
        self,
        request: BoundToolRequest,
        execution: AdapterExecution,
        *,
        now: datetime,
    ) -> ToolVerification:
        del execution
        with self._lock:
            observed = self._observed_state(request)
        verified = observed == dict(request.request.expected_state)
        return ToolVerification(
            uuid4(),
            request.request.id,
            VerificationOutcome.VERIFIED if verified else VerificationOutcome.FAILED,
            observed,
            request.request.evidence,
            None if verified else PolicyReason.VERIFICATION_FAILED,
            now,
        )

    def _block_ip(self, request: BoundToolRequest) -> AdapterExecution:
        target = str(request.request.arguments["target_ip"])
        state = self._firewall_state(request)
        fail_once = self._consume_failure("block_ip", use_firewall_state=True)
        outcome = self._firewall.block_ip(
            state,
            IPv4Address(target),
            request.request.idempotency_key,
            fail_once=fail_once,
        )
        self._firewalls[target] = outcome.state
        if outcome.result.status is ToolCallStatus.FAILED:
            return AdapterExecution(
                ExecutionOutcome.FAILED,
                "Firewall simulation rejected the change.",
                outcome.result.error_code or "simulation_failure",
            )
        return AdapterExecution(ExecutionOutcome.SUCCEEDED, "Firewall simulation change completed.")

    def _isolate_endpoint(self, request: BoundToolRequest) -> AdapterExecution:
        target = str(request.request.arguments["endpoint_id"])
        self._require_target(self._endpoints, target, "endpoint")
        if self._consume_failure("isolate_endpoint"):
            return AdapterExecution(
                ExecutionOutcome.FAILED,
                "Endpoint simulation rejected the change.",
                "simulated_endpoint_failure",
            )
        self._endpoints[target] = "isolated"
        return AdapterExecution(ExecutionOutcome.SUCCEEDED, "Endpoint simulation change completed.")

    def _disable_account(self, request: BoundToolRequest) -> AdapterExecution:
        target = str(request.request.arguments["account_id"])
        self._require_target(self._accounts, target, "account")
        if self._consume_failure("disable_account"):
            return AdapterExecution(
                ExecutionOutcome.FAILED,
                "Account simulation rejected the change.",
                "simulated_account_failure",
            )
        self._accounts[target] = "disabled"
        return AdapterExecution(ExecutionOutcome.SUCCEEDED, "Account simulation change completed.")

    def _observed_state(self, request: BoundToolRequest) -> dict[str, str]:
        name = request.registration.definition.name
        if name in {"query_firewall_state", "block_ip"}:
            state = self._firewall_state(request)
            return {"firewall_status": state.firewall_status}
        if name in {"query_endpoint_state", "isolate_endpoint"}:
            return {"isolation_status": self._endpoint_state(request)}
        if name in {"query_account_state", "disable_account"}:
            return {"account_status": self._account_state(request)}
        raise ValueError("tool has no offline verifier")

    def _firewall_state(self, request: BoundToolRequest):
        target = str(request.request.arguments["target_ip"])
        self._require_target(self._firewalls, target, "firewall")
        return self._firewalls[target]

    def _endpoint_state(self, request: BoundToolRequest) -> str:
        target = str(request.request.arguments["endpoint_id"])
        self._require_target(self._endpoints, target, "endpoint")
        return self._endpoints[target]

    def _account_state(self, request: BoundToolRequest) -> str:
        target = str(request.request.arguments["account_id"])
        self._require_target(self._accounts, target, "account")
        return self._accounts[target]

    def _consume_failure(self, tool: str, *, use_firewall_state: bool = False) -> bool:
        if tool not in self._fail_once:
            return False
        if not use_firewall_state:
            self._fail_once.remove(tool)
        return True

    @staticmethod
    def _require_target(values: dict[str, object], target: str, kind: str) -> None:
        if target not in values:
            raise SimulationTargetRejected(f"{kind} target is not in the simulation allowlist")
