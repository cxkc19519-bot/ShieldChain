"""Read-only HTTP boundary for the public multi-agent trajectory."""

from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request

from shieldchain.agents.schemas import CollaborationTrajectoryView
from shieldchain.agents.trajectory import (
    CollaborationTrajectoryNotFound,
    CollaborationTrajectoryQuery,
)
from shieldchain.core.errors import ApiError

router = APIRouter(tags=["agents"])


@router.get(
    "/agents/runs/{run_id}/trajectory",
    response_model=CollaborationTrajectoryView,
)
def get_collaboration_trajectory(run_id: UUID, request: Request) -> CollaborationTrajectoryView:
    query = cast(CollaborationTrajectoryQuery, request.app.state.agent_trajectory_query)
    tenant_id = cast(UUID, request.app.state.rag_demo_tenant_id)
    try:
        return query.get(tenant_id=tenant_id, run_id=run_id)
    except CollaborationTrajectoryNotFound:
        raise ApiError("agent_trajectory_not_found", "Agent trajectory not found", 404) from None
