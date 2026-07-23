from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.context import ContextAssemblyService
from shieldchain.agents.domain import AgentRole
from shieldchain.agents.roles import (
    DeterministicFakeRoleModel,
    ProfessionalRoleRegistry,
    RoleExecutionRequest,
    RoleExecutionStatus,
    StrictModelRole,
    build_offline_role_registry,
)
from shieldchain.agents.security import ServerAccessContext
from shieldchain.incidents.scenario import collect_evidence, seed_phishing_scenario
from shieldchain.rag.domain import RefusalReason, SensitivityLevel, StructuredRefusal

NOW = datetime(2026, 7, 23, 1, tzinfo=UTC)
CASE = UUID("10000000-0000-0000-0000-000000000001")


def context(role: AgentRole, *, facts: bool = True):
    case = {"case_id": str(CASE), "phase": "investigation"}
    if facts:
        case["confirmed_facts"] = [{"statement": "confirmed"}]
    return ContextAssemblyService(now=NOW).assemble(
        access=ServerAccessContext(
            CASE,
            uuid4(),
            role,
            ("analyst",),
            (SensitivityLevel.INTERNAL,),
            ("soc",),
        ),
        system_rules=("system",),
        safety_boundaries=("safety",),
        current_task="Investigate phishing behavior",
        allowed_actions=("block_ip", "isolate_endpoint"),
        case_tenant_id=CASE,
        case_sensitivity=SensitivityLevel.INTERNAL,
        case_permission_tags=("soc",),
        case_summary=case,
        candidates=(),
        output_schema={"summary": "string"},
        max_tokens=1000,
    )


class EvidencePort:
    def fetch(self, **_kwargs):
        state = seed_phishing_scenario(NOW)
        return collect_evidence(state, NOW)


class KnowledgePort:
    def __init__(self, decision=None, error=None):
        self.decision = decision
        self.error = error

    def retrieve(self, **kwargs):
        if self.error:
            raise self.error
        return self.decision or StructuredRefusal(
            RefusalReason.INSUFFICIENT_EVIDENCE,
            "insufficient",
            kwargs["query"],
            (),
            (),
        )


def request(role: AgentRole, *, facts: bool = True):
    return RoleExecutionRequest(role, CASE, context(role, facts=facts), NOW)


def test_default_registry_contains_all_roles_and_triage_reuses_incident_rules() -> None:
    registry = build_offline_role_registry(
        evidence_port=EvidencePort(), knowledge_port=KnowledgePort()
    )
    triage = registry.execute(request(AgentRole.ALERT_TRIAGE))
    investigation = registry.execute(request(AgentRole.THREAT_INVESTIGATION))
    assert triage.status is RoleExecutionStatus.COMPLETED
    assert len(triage.output.references) == 5
    assert triage.output.risks[0].severity == "high"
    assert investigation.status is RoleExecutionStatus.COMPLETED


def test_knowledge_refusal_and_timeout_propagate_explicitly() -> None:
    refused = build_offline_role_registry(
        evidence_port=EvidencePort(), knowledge_port=KnowledgePort()
    ).execute(request(AgentRole.KNOWLEDGE_RETRIEVAL))
    assert refused.status is RoleExecutionStatus.REFUSED
    assert refused.error_code == "rag_insufficient_evidence"

    timed_out = build_offline_role_registry(
        evidence_port=EvidencePort(), knowledge_port=KnowledgePort(error=TimeoutError())
    ).execute(request(AgentRole.KNOWLEDGE_RETRIEVAL))
    assert timed_out.status is RoleExecutionStatus.TIMED_OUT
    assert timed_out.output is None


def test_response_role_returns_proposals_and_never_tool_results() -> None:
    result = build_offline_role_registry(
        evidence_port=EvidencePort(), knowledge_port=KnowledgePort()
    ).execute(request(AgentRole.RESPONSE_PLANNING))
    assert result.status is RoleExecutionStatus.COMPLETED
    assert result.output.recommended_actions == (
        "proposed:block_ip",
        "proposed:isolate_endpoint",
    )
    assert "invoked" in result.output.summary


@pytest.mark.parametrize("role", (AgentRole.VERIFICATION, AgentRole.REPORTING))
def test_verification_and_reporting_require_trusted_facts(role: AgentRole) -> None:
    registry = build_offline_role_registry(
        evidence_port=EvidencePort(), knowledge_port=KnowledgePort()
    )
    assert registry.execute(request(role)).status is RoleExecutionStatus.COMPLETED
    refused = registry.execute(request(role, facts=False))
    assert refused.status is RoleExecutionStatus.REFUSED
    assert refused.error_code == "trusted_facts_missing"


class BadModel:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error

    def complete(self, **_kwargs):
        if self.error:
            raise self.error
        return self.value


def test_model_adapter_rejects_malformed_output_and_propagates_timeout() -> None:
    bad = StrictModelRole(AgentRole.REPORTING, BadModel({"summary": "x", "extra": "y"}))
    assert bad.execute(request(AgentRole.REPORTING)).status is RoleExecutionStatus.INVALID_OUTPUT
    timeout = StrictModelRole(AgentRole.REPORTING, BadModel(error=TimeoutError()))
    assert timeout.execute(request(AgentRole.REPORTING)).status is RoleExecutionStatus.TIMED_OUT
    fake = StrictModelRole(AgentRole.REPORTING, DeterministicFakeRoleModel())
    assert fake.execute(request(AgentRole.REPORTING)).status is RoleExecutionStatus.COMPLETED


def test_registry_rejects_missing_role() -> None:
    with pytest.raises(ValueError, match="every agent role"):
        ProfessionalRoleRegistry({})
