from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.context import ContextAssemblyCandidate, ContextAssemblyService
from shieldchain.agents.domain import AgentRole
from shieldchain.agents.security import AccessDenied, ContextContentType, ServerAccessContext
from shieldchain.rag.domain import SensitivityLevel

NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
TENANT = UUID("10000000-0000-0000-0000-000000000001")
OTHER_TENANT = UUID("20000000-0000-0000-0000-000000000002")


def access() -> ServerAccessContext:
    return ServerAccessContext(
        tenant_id=TENANT,
        principal_id=uuid4(),
        agent_role=AgentRole.THREAT_INVESTIGATION,
        principal_roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=("soc",),
    )


def assemble(case_tenant_id: UUID = TENANT):
    return ContextAssemblyService(now=NOW).assemble(
        access=access(),
        system_rules=("system",),
        safety_boundaries=("safety",),
        current_task="task",
        allowed_actions=("read",),
        case_tenant_id=case_tenant_id,
        case_sensitivity=SensitivityLevel.INTERNAL,
        case_permission_tags=("soc",),
        case_summary={
            "case_id": "case-42",
            "phase": "investigation",
            "tenant_id": "client-override",
            "raw_prompt": "hidden",
            "confirmed_facts": [{"statement": "safe", "principal_id": "hidden"}],
        },
        candidates=(),
        output_schema={"summary": "string"},
        max_tokens=1000,
    )


def test_case_summary_is_projected_and_cannot_override_server_authority() -> None:
    prompt = assemble().to_prompt()
    assert "case-42" in prompt
    assert "client-override" not in prompt
    assert "raw_prompt" not in prompt
    assert "principal_id" not in prompt


def test_cross_tenant_case_summary_fails_closed() -> None:
    with pytest.raises(AccessDenied, match="tenant"):
        assemble(OTHER_TENANT)


def test_candidate_defensively_freezes_nested_payload() -> None:
    nested = {"excerpt": "safe", "metadata": {"values": ["one"]}}
    item = ContextAssemblyCandidate(
        content_type=ContextContentType.EVIDENCE,
        tenant_id=TENANT,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags=("soc",),
        source_id="edr:1",
        payload=nested,
        relevance=1,
        observed_at=NOW,
    )

    nested["excerpt"] = "mutated"
    nested["metadata"]["values"].append("two")  # type: ignore[index,union-attr]
    assert item.payload["excerpt"] == "safe"
    assert item.payload["metadata"]["values"] == ("one",)  # type: ignore[index]


def test_permission_tags_reject_string_instead_of_splitting_characters() -> None:
    with pytest.raises(TypeError, match="permission_tags"):
        ContextAssemblyCandidate(
            content_type=ContextContentType.EVIDENCE,
            tenant_id=TENANT,
            sensitivity=SensitivityLevel.INTERNAL,
            permission_tags="soc",  # type: ignore[arg-type]
            source_id="edr:1",
            payload={"excerpt": "safe"},
            relevance=1,
            observed_at=NOW,
        )
