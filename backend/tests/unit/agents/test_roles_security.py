from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.context import ContextAssemblyService
from shieldchain.agents.domain import AgentRole
from shieldchain.agents.roles import (
    OfflineKnowledgeRole,
    RoleExecutionRequest,
    RoleExecutionStatus,
    StrictModelRole,
)
from shieldchain.agents.security import ServerAccessContext
from shieldchain.rag.answering import GroundedAnswer, RiskLevel
from shieldchain.rag.domain import Citation, SensitivityLevel

NOW = datetime(2026, 7, 23, 1, tzinfo=UTC)
CASE = UUID("10000000-0000-0000-0000-000000000001")


def context(role: AgentRole):
    return ContextAssemblyService(now=NOW).assemble(
        access=ServerAccessContext(
            CASE, uuid4(), role, ("analyst",), (SensitivityLevel.INTERNAL,), ("soc",)
        ),
        system_rules=("system",),
        safety_boundaries=("safety",),
        current_task="Find phishing guidance",
        allowed_actions=("block_ip",),
        case_tenant_id=CASE,
        case_sensitivity=SensitivityLevel.INTERNAL,
        case_permission_tags=("soc",),
        case_summary={"case_id": str(CASE), "confirmed_facts": []},
        candidates=(),
        output_schema={"summary": "string"},
        max_tokens=1000,
    )


class GroundedPort:
    def retrieve(self, **_kwargs):
        citation = Citation(
            uuid4(),
            uuid4(),
            uuid4(),
            uuid4(),
            ("IR",),
            2,
            None,
            "Block the malicious indicator after validation.",
            0.8,
            0.8,
            0.9,
            0.9,
            NOW,
            "a" * 64,
        )
        return GroundedAnswer(
            "query",
            "Grounded guidance",
            (citation,),
            (citation,),
            (),
            RiskLevel.LOW,
        )


def test_knowledge_role_converts_grounded_citations_to_trusted_case_references() -> None:
    role = OfflineKnowledgeRole(GroundedPort())
    result = role.execute(
        RoleExecutionRequest(AgentRole.KNOWLEDGE_RETRIEVAL, CASE, context(role.role), NOW)
    )
    assert result.status is RoleExecutionStatus.COMPLETED
    assert result.output.summary == "Grounded guidance"
    assert len(result.output.references) == 1
    assert result.output.references[0].case_id == CASE


class PlanningModel:
    def complete(self, **_kwargs):
        return {"summary": "Plan only", "recommended_actions": ["block_ip"]}


def test_model_response_role_can_only_return_proposed_actions() -> None:
    role = StrictModelRole(AgentRole.RESPONSE_PLANNING, PlanningModel())
    result = role.execute(
        RoleExecutionRequest(AgentRole.RESPONSE_PLANNING, CASE, context(role.role), NOW)
    )
    assert result.output.recommended_actions == ("proposed:block_ip",)


def test_knowledge_role_cannot_be_replaced_by_generic_model_adapter() -> None:
    with pytest.raises(ValueError, match="grounded RAG"):
        StrictModelRole(AgentRole.KNOWLEDGE_RETRIEVAL, PlanningModel())
