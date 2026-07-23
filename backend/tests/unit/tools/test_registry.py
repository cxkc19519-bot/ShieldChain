from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import (
    ToolDefinition,
    ToolRisk,
    ToolTargetType,
    TrustedToolRequest,
)
from shieldchain.tools.registry import (
    DuplicateToolRegistration,
    ToolNotRegistered,
    ToolParameterRejected,
    ToolParameterSchema,
    ToolRegistration,
    TrustedToolRegistry,
    UnsafeToolRegistration,
    default_tool_registry,
)

NOW = datetime(2026, 7, 23, 6, tzinfo=UTC)
CASE, RUN, PLAN, REQUEST, EVIDENCE = (UUID(int=value) for value in range(1001, 1006))
REF = EvidenceReference(EVIDENCE, CASE, "siem:1", NOW, "a" * 64)


def tool_request(**changes: object) -> TrustedToolRequest:
    values = dict(
        id=REQUEST,
        case_id=CASE,
        run_id=RUN,
        plan_id=PLAN,
        idempotency_key="phase5:block:1001",
        caller_role=AgentRole.RESPONSE_PLANNING,
        tool_name="block_ip",
        tool_version="1",
        arguments={"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        expected_state={"firewall_status": "blocked"},
        rollback_strategy="Remove the exact scoped firewall rule.",
        evidence=(REF,),
        created_at=NOW,
    )
    values.update(changes)
    return TrustedToolRequest(**values)


def test_default_registry_contains_fixed_tools_and_read_only_verifiers() -> None:
    registry = default_tool_registry()
    identities = {item.definition.identity for item in registry.registrations}
    assert {
        ("query_firewall_state", "1"),
        ("block_ip", "1"),
        ("query_endpoint_state", "1"),
        ("isolate_endpoint", "1"),
        ("query_account_state", "1"),
        ("disable_account", "1"),
    } == identities
    assert registry.resolve("block_ip", "1").definition.risk is ToolRisk.HIGH
    assert registry.resolve("disable_account", "1").definition.risk is ToolRisk.CRITICAL


def test_bind_normalizes_parameters_and_produces_stable_digests() -> None:
    registry = default_tool_registry()
    first = registry.bind(
        tool_request(arguments={"rule_ttl_seconds": 3600, "target_ip": "203.0.113.8"})
    )
    second = registry.bind(tool_request())
    assert dict(first.request.arguments) == {
        "rule_ttl_seconds": 3600,
        "target_ip": "203.0.113.8",
    }
    assert first.request_digest == second.request_digest
    assert first.arguments_digest == second.arguments_digest


@pytest.mark.parametrize(
    "arguments",
    (
        {"target_ip": "203.0.113.8"},
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 59},
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600, "extra": True},
        {"target_ip": "127.0.0.1", "rule_ttl_seconds": 3600},
        {"target_ip": "224.0.0.1", "rule_ttl_seconds": 3600},
    ),
)
def test_block_schema_rejects_missing_extra_range_and_unsafe_targets(arguments) -> None:
    with pytest.raises(ToolParameterRejected):
        default_tool_registry().bind(tool_request(arguments=arguments))


def test_unknown_tool_and_version_are_indistinguishable() -> None:
    registry = default_tool_registry()
    with pytest.raises(ToolNotRegistered, match="name or version"):
        registry.bind(tool_request(tool_name="unknown_tool"))
    with pytest.raises(ToolNotRegistered, match="name or version"):
        registry.bind(tool_request(tool_version="2"))


def test_endpoint_and_account_schemas_use_enumerated_reasons_and_exact_state() -> None:
    registry = default_tool_registry()
    isolated = registry.bind(
        tool_request(
            tool_name="isolate_endpoint",
            arguments={"endpoint_id": "host-42", "reason_code": "confirmed_compromise"},
            expected_state={"isolation_status": "isolated"},
        )
    )
    assert isolated.request.arguments["endpoint_id"] == "host-42"
    with pytest.raises(ToolParameterRejected, match="reason_code"):
        registry.bind(
            tool_request(
                tool_name="disable_account",
                arguments={"account_id": "user-42", "reason_code": "model_said_so"},
                expected_state={"account_status": "disabled"},
            )
        )
    with pytest.raises(ToolParameterRejected, match="expected_state"):
        registry.bind(
            tool_request(
                tool_name="isolate_endpoint",
                arguments={"endpoint_id": "host-42", "reason_code": "containment_required"},
                expected_state={"isolation_status": "isolated", "extra": "hidden"},
            )
        )


def test_registry_rejects_duplicate_and_unsafe_verifier_relationships() -> None:
    query = default_tool_registry().resolve("query_firewall_state", "1")
    with pytest.raises(DuplicateToolRegistration):
        TrustedToolRegistry((query, query))
    unsafe_query = ToolRegistration(
        ToolDefinition(
            "query_firewall_state",
            "1",
            ToolTargetType.IPV4,
            ToolRisk.LOW,
            frozenset({AgentRole.VERIFICATION}),
            1,
            0,
            False,
            None,
        ),
        ToolParameterSchema.FIREWALL_QUERY_V1,
    )
    block = default_tool_registry().resolve("block_ip", "1")
    with pytest.raises(UnsafeToolRegistration, match="read-only"):
        TrustedToolRegistry((unsafe_query, block))


def test_registration_rejects_schema_target_mismatch() -> None:
    definition = replace(
        default_tool_registry().resolve("block_ip", "1").definition,
        target_type=ToolTargetType.ACCOUNT,
    )
    with pytest.raises(UnsafeToolRegistration, match="target"):
        ToolRegistration(definition, ToolParameterSchema.BLOCK_IP_V1)
