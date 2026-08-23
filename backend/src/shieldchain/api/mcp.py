from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request

from shieldchain.core.errors import ApiError
from shieldchain.operations.audit import AgentToolAuditStore, AgentToolRunNotFound
from shieldchain.operations.schemas import AgentToolCallAuditListResponse

router = APIRouter(prefix="/mcp/runs", tags=["mcp"])


@router.get("/{run_id}/calls", response_model=AgentToolCallAuditListResponse)
def list_agent_tool_calls(run_id: UUID, request: Request) -> AgentToolCallAuditListResponse:
    store = cast(AgentToolAuditStore, request.app.state.agent_tool_audit_store)
    tenant_id = cast(UUID, request.app.state.rag_demo_tenant_id)
    try:
        return AgentToolCallAuditListResponse(
            items=store.list_for_run(tenant_id=tenant_id, run_id=run_id)
        )
    except AgentToolRunNotFound:
        raise ApiError("agent_tool_run_not_found", "Agent tool run not found", 404) from None
