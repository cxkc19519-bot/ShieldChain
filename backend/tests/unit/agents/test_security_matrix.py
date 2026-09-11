from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import AgentRole
from shieldchain.agents.security import (
    AccessDenied,
    ContextAccessPolicy,
    ContextContentType,
    ServerAccessContext,
)
from shieldchain.rag.domain import SensitivityLevel

TENANT = UUID("10000000-0000-0000-0000-000000000001")

_EXPECTED_ROLES = {
    ContextContentType.SHARED_CASE: frozenset(AgentRole),
    ContextContentType.ROLE_PRIVATE: frozenset({AgentRole.THREAT_INVESTIGATION}),
    ContextContentType.HANDOFF: frozenset(
        {
            AgentRole.SUPERAGENT,
            AgentRole.ALERT_TRIAGE,
            AgentRole.THREAT_INVESTIGATION,
        }
    ),
    ContextContentType.EVIDENCE: frozenset(
        {
            AgentRole.SUPERAGENT,
            AgentRole.ALERT_TRIAGE,
            AgentRole.THREAT_INVESTIGATION,
            AgentRole.VERIFICATION,
            AgentRole.REPORTING,
        }
    ),
    ContextContentType.KNOWLEDGE: frozenset(
        {AgentRole.SUPERAGENT, AgentRole.KNOWLEDGE_RETRIEVAL, AgentRole.REPORTING}
    ),
    ContextContentType.USER_INPUT: frozenset({AgentRole.SUPERAGENT}),
    ContextContentType.TOOL_RESULT: frozenset(
        {AgentRole.SUPERAGENT, AgentRole.VERIFICATION, AgentRole.REPORTING}
    ),
}


@pytest.mark.parametrize("content_type", tuple(ContextContentType))
@pytest.mark.parametrize("role", tuple(AgentRole))
def test_agent_content_permission_matrix(
    role: AgentRole, content_type: ContextContentType
) -> None:
    access = ServerAccessContext(
        tenant_id=TENANT,
        principal_id=uuid4(),
        agent_role=role,
        principal_roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=("soc",),
    )
    kwargs = {
        "content_type": content_type,
        "tenant_id": TENANT,
        "sensitivity": SensitivityLevel.INTERNAL,
        "permission_tags": ("soc",),
        "payload": {"case_id": "case-42", "id": "item-42", "message": "data"},
        "owner_role": AgentRole.THREAT_INVESTIGATION,
        "participant_roles": (
            AgentRole.ALERT_TRIAGE,
            AgentRole.THREAT_INVESTIGATION,
        ),
    }

    if role in _EXPECTED_ROLES[content_type]:
        assert isinstance(ContextAccessPolicy().project(access, **kwargs), dict)
    else:
        with pytest.raises(AccessDenied):
            ContextAccessPolicy().project(access, **kwargs)
