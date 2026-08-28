"""Server-authorized ReAct trajectory and human control endpoints."""

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.react.api_service import ReactApiNotFound, ReactApiService, ReactControlConflict
from shieldchain.react.schemas import ReactControlInput, ReactMutationView, ReactTrajectoryView

router = APIRouter(tags=["react"])


def _service(request: Request) -> ReactApiService:
    return cast(ReactApiService, request.app.state.react_api_service)


def _authority(request: Request) -> tuple[UUID, UUID]:
    return (
        cast(UUID, request.app.state.rag_demo_tenant_id),
        cast(UUID, request.app.state.rag_demo_principal_id),
    )


def _require_operator_control(request: Request) -> None:
    settings = cast(Settings, request.app.state.settings)
    if settings.environment == "production":
        raise ApiError(
            "operator_auth_required",
            "Operator controls require an authenticated administrator boundary",
            403,
        )


@router.get("/react/runs/{run_id}/trajectory", response_model=ReactTrajectoryView)
def trajectory(run_id: UUID, request: Request) -> ReactTrajectoryView:
    tenant_id, _ = _authority(request)
    try:
        return _service(request).trajectory(tenant_id=tenant_id, run_id=run_id)
    except ReactApiNotFound:
        raise ApiError("react_trajectory_not_found", "ReAct trajectory not found", 404) from None


@router.post("/react/loops/{loop_id}/{action}", response_model=ReactMutationView)
def control(
    loop_id: UUID, action: str, payload: ReactControlInput, request: Request
) -> ReactMutationView:
    _require_operator_control(request)
    if action not in {"takeover", "resume"}:
        raise ApiError("react_control_invalid", "Unsupported ReAct control", 404)
    tenant_id, actor_id = _authority(request)
    try:
        return _service(request).control(
            tenant_id=tenant_id,
            actor_id=actor_id,
            loop_id=loop_id,
            action=action,
            reason=payload.reason,
            request_id=cast(str, request.state.request_id),
            now=datetime.now(UTC),
        )
    except ReactApiNotFound:
        raise ApiError("react_loop_not_found", "ReAct loop not found", 404) from None
    except ReactControlConflict:
        raise ApiError("react_control_conflict", "ReAct control is not allowed", 409) from None
