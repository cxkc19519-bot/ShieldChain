"""Server-authorized trusted-tool trace and control endpoints."""

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request

from shieldchain.core.errors import ApiError
from shieldchain.tools.api_service import ToolApiNotFound, TrustedToolApiService
from shieldchain.tools.approvals import ApprovalError
from shieldchain.tools.control import ToolControlError
from shieldchain.tools.domain import ApprovalOutcome
from shieldchain.tools.plan_service import (
    ResponsePlanDecisionConflict,
    ResponsePlanDecisionNotFound,
)
from shieldchain.tools.schemas import (
    ResponsePlanDecisionInput,
    ResponsePlanMutationView,
    ToolControlInput,
    ToolDecisionInput,
    ToolEmergencyInput,
    ToolMutationView,
    ToolTraceView,
)

router = APIRouter(tags=["tools"])


def _service(request: Request) -> TrustedToolApiService:
    return cast(TrustedToolApiService, request.app.state.trusted_tool_api_service)


def _authority(request: Request) -> tuple[UUID, UUID]:
    return (
        cast(UUID, request.app.state.rag_demo_tenant_id),
        cast(UUID, request.app.state.rag_demo_principal_id),
    )


@router.get("/tools/runs/{run_id}/calls", response_model=ToolTraceView)
def trace(run_id: UUID, request: Request) -> ToolTraceView:
    tenant_id, _ = _authority(request)
    try:
        return _service(request).trace(tenant_id=tenant_id, run_id=run_id)
    except ToolApiNotFound:
        raise ApiError(
            "trusted_tool_trace_not_found", "Trusted tool trace not found", 404
        ) from None


@router.post("/tools/plans/{plan_id}/decision", response_model=ResponsePlanMutationView)
def decide_plan(
    plan_id: UUID,
    payload: ResponsePlanDecisionInput,
    request: Request,
) -> ResponsePlanMutationView:
    tenant_id, actor_id = _authority(request)
    try:
        return _service(request).decide_plan(
            tenant_id=tenant_id,
            actor_id=actor_id,
            plan_id=plan_id,
            outcome=payload.outcome,
            reason=payload.reason,
            now=datetime.now(UTC),
        )
    except ResponsePlanDecisionNotFound:
        raise ApiError("response_plan_not_found", "Response plan not found", 404) from None
    except ResponsePlanDecisionConflict:
        raise ApiError(
            "response_plan_decision_conflict",
            "Response plan decision is not allowed",
            409,
        ) from None


@router.post("/tools/calls/{call_id}/approval", response_model=ToolMutationView)
def approve(call_id: UUID, payload: ToolDecisionInput, request: Request) -> ToolMutationView:
    tenant_id, actor_id = _authority(request)
    try:
        return _service(request).decide(
            tenant_id=tenant_id,
            actor_id=actor_id,
            call_id=call_id,
            outcome=ApprovalOutcome(payload.outcome),
            reason=payload.reason,
            now=datetime.now(UTC),
        )
    except ToolApiNotFound:
        raise ApiError("trusted_tool_call_not_found", "Trusted tool call not found", 404) from None
    except ApprovalError:
        raise ApiError(
            "trusted_tool_approval_conflict", "Trusted tool approval is not allowed", 409
        ) from None


@router.post("/tools/calls/{call_id}/{action}", response_model=ToolMutationView)
def control(
    call_id: UUID, action: str, payload: ToolControlInput, request: Request
) -> ToolMutationView:
    if action not in {"pause", "resume", "cancel"}:
        raise ApiError("trusted_tool_control_invalid", "Unsupported tool control", 404)
    tenant_id, actor_id = _authority(request)
    try:
        return _service(request).control_call(
            tenant_id=tenant_id,
            actor_id=actor_id,
            call_id=call_id,
            action=action,
            reason=payload.reason,
            now=datetime.now(UTC),
        )
    except ToolApiNotFound:
        raise ApiError("trusted_tool_call_not_found", "Trusted tool call not found", 404) from None
    except ToolControlError:
        raise ApiError(
            "trusted_tool_control_conflict", "Trusted tool control is not allowed", 409
        ) from None


@router.post("/tools/emergency-stop", response_model=ToolMutationView)
def emergency(payload: ToolEmergencyInput, request: Request) -> ToolMutationView:
    tenant_id, actor_id = _authority(request)
    return _service(request).emergency(
        tenant_id=tenant_id,
        actor_id=actor_id,
        active=payload.active,
        reason=payload.reason,
        now=datetime.now(UTC),
    )
