"""Deterministic, default-deny policy engine for bound trusted tool requests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from shieldchain.agents.domain import AgentRole
from shieldchain.tools.domain import (
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolRisk,
    ToolTargetType,
)
from shieldchain.tools.registry import BoundToolRequest


class ToolExecutionMode(StrEnum):
    SIMULATION = "simulation"
    REAL = "real"


@dataclass(frozen=True, slots=True)
class ToolPolicyContext:
    tenant_id: UUID
    principal_id: UUID
    case_id: UUID
    run_id: UUID
    role: AgentRole
    mode: ToolExecutionMode
    automation_enabled: bool
    emergency_stop_active: bool
    allowed_tools: frozenset[tuple[str, str]]
    allowed_targets: Mapping[ToolTargetType, frozenset[str]]
    confirmed_evidence_ids: frozenset[UUID]
    tool_calls_used: int
    tool_call_limit: int
    calls_in_window: int
    rate_limit: int
    simulation_auto_approve_critical: bool
    now: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "principal_id", "case_id", "run_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if not isinstance(self.role, AgentRole):
            raise TypeError("role must be an AgentRole")
        if not isinstance(self.mode, ToolExecutionMode):
            raise TypeError("mode must be a ToolExecutionMode")
        tools = frozenset(self.allowed_tools)
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or any(not isinstance(value, str) for value in item)
            for item in tools
        ):
            raise TypeError("allowed_tools must contain name/version pairs")
        object.__setattr__(self, "allowed_tools", tools)
        targets = {key: frozenset(values) for key, values in self.allowed_targets.items()}
        if any(not isinstance(key, ToolTargetType) for key in targets):
            raise TypeError("allowed_targets keys must be ToolTargetType values")
        object.__setattr__(self, "allowed_targets", MappingProxyType(targets))
        evidence = frozenset(self.confirmed_evidence_ids)
        if any(not isinstance(value, UUID) for value in evidence):
            raise TypeError("confirmed_evidence_ids must contain UUID values")
        object.__setattr__(self, "confirmed_evidence_ids", evidence)
        for used, limit, label in (
            (self.tool_calls_used, self.tool_call_limit, "tool call budget"),
            (self.calls_in_window, self.rate_limit, "rate limit"),
        ):
            if (
                not isinstance(used, int)
                or isinstance(used, bool)
                or not isinstance(limit, int)
                or isinstance(limit, bool)
                or used < 0
                or limit < 0
            ):
                raise ValueError(f"{label} values must be non-negative integers")
        if self.now.tzinfo is None or self.now.utcoffset() != timedelta(0):
            raise ValueError("now must be an aware UTC datetime")


class DeterministicToolPolicy:
    version = "phase5-policy-v1"

    def evaluate(self, bound: BoundToolRequest, context: ToolPolicyContext) -> PolicyDecision:
        request = bound.request
        definition = bound.registration.definition
        outcome = PolicyOutcome.DENY
        reason = PolicyReason.POLICY_ALLOWED
        if not context.automation_enabled:
            reason = PolicyReason.AUTOMATION_DISABLED
        elif context.emergency_stop_active:
            reason = PolicyReason.EMERGENCY_STOP_ACTIVE
        elif definition.identity not in context.allowed_tools:
            reason = PolicyReason.TOOL_NOT_ALLOWED
        elif (
            request.caller_role is not context.role or context.role not in definition.allowed_roles
        ):
            reason = PolicyReason.CALLER_NOT_ALLOWED
        elif request.case_id != context.case_id or request.run_id != context.run_id:
            reason = PolicyReason.CASE_BINDING_INVALID
        elif not request.evidence:
            reason = PolicyReason.EVIDENCE_REQUIRED
        elif any(item.id not in context.confirmed_evidence_ids for item in request.evidence):
            reason = PolicyReason.EVIDENCE_INVALID
        elif self._target(bound) not in context.allowed_targets.get(
            definition.target_type, frozenset()
        ):
            reason = PolicyReason.TARGET_OUT_OF_SCOPE
        elif context.tool_calls_used >= context.tool_call_limit:
            reason = PolicyReason.BUDGET_EXHAUSTED
        elif context.calls_in_window >= context.rate_limit:
            reason = PolicyReason.RATE_LIMITED
        else:
            outcome, reason = self._risk_decision(definition.risk, context)
        return PolicyDecision(
            request.id,
            outcome,
            reason,
            self.version,
            definition.risk,
            context.now,
            context.now + timedelta(minutes=5),
        )

    @staticmethod
    def _target(bound: BoundToolRequest) -> str:
        arguments = bound.request.arguments
        for key in ("target_ip", "endpoint_id", "account_id"):
            if key in arguments:
                return str(arguments[key])
        return ""

    @staticmethod
    def _risk_decision(
        risk: ToolRisk, context: ToolPolicyContext
    ) -> tuple[PolicyOutcome, PolicyReason]:
        if risk in {ToolRisk.READ_ONLY, ToolRisk.LOW}:
            return PolicyOutcome.ALLOW, PolicyReason.POLICY_ALLOWED
        if context.mode is ToolExecutionMode.SIMULATION and (
            risk is not ToolRisk.CRITICAL or context.simulation_auto_approve_critical
        ):
            return PolicyOutcome.ALLOW, PolicyReason.AUTOMATIC_SIMULATION_APPROVAL
        return PolicyOutcome.APPROVAL_REQUIRED, PolicyReason.APPROVAL_REQUIRED
