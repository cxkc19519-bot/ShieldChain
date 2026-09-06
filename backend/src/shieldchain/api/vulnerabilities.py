from __future__ import annotations

from typing import cast
from uuid import UUID

from fastapi import APIRouter, Header, Request, status

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.vulnerabilities.schemas import (
    VulnerabilityChangeRequest,
    VulnerabilityDecisionRequest,
    VulnerabilityFindingIngestRequest,
    VulnerabilityFindingIngestResponse,
    VulnerabilityFindingListResponse,
    VulnerabilityFindingView,
    VulnerabilityImplementationRequest,
    VulnerabilityMetricsView,
    VulnerabilityMutationView,
    VulnerabilityTriageRequest,
    VulnerabilityVerificationRequest,
)
from shieldchain.vulnerabilities.service import (
    VulnerabilityNotFound,
    VulnerabilityWorkflowError,
    VulnerabilityWorkflowService,
)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


def _service(request: Request) -> VulnerabilityWorkflowService:
    return request.app.state.vulnerability_workflow_service


def _require_operator_control(request: Request) -> None:
    settings = cast(Settings, request.app.state.settings)
    if settings.environment == "production" and not settings.response_operator_controls_enabled:
        raise ApiError(
            "operator_auth_required",
            "Vulnerability workflow changes require an authenticated administrator boundary",
            403,
        )


def _call(action):
    try:
        return action()
    except VulnerabilityNotFound as error:
        raise ApiError("vulnerability_not_found", str(error), 404) from None
    except VulnerabilityWorkflowError as error:
        raise ApiError("vulnerability_transition_rejected", str(error), 409) from None


@router.post(
    "/findings",
    response_model=VulnerabilityFindingIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_finding(
    payload: VulnerabilityFindingIngestRequest,
    request: Request,
    scanner_token: str | None = Header(default=None, alias="X-ShieldChain-Vulnerability-Token"),
) -> VulnerabilityFindingIngestResponse:
    service = _service(request)
    if not service.scanner_authorized(scanner_token):
        raise ApiError("vulnerability_ingestion_unauthorized", "scanner authentication failed", 401)
    return service.ingest(payload)


@router.get("/findings", response_model=VulnerabilityFindingListResponse)
def list_findings(request: Request) -> VulnerabilityFindingListResponse:
    return _service(request).list()


@router.get("/findings/{finding_id}", response_model=VulnerabilityFindingView)
def get_finding(finding_id: UUID, request: Request) -> VulnerabilityFindingView:
    return _call(lambda: _service(request).get(finding_id))


@router.get("/metrics", response_model=VulnerabilityMetricsView)
def metrics(request: Request) -> VulnerabilityMetricsView:
    return _service(request).metrics()


@router.post(
    "/findings/{finding_id}/triage", response_model=VulnerabilityMutationView, status_code=201
)
async def triage(
    finding_id: UUID, payload: VulnerabilityTriageRequest, request: Request
) -> VulnerabilityMutationView:
    _require_operator_control(request)
    try:
        return await _service(request).triage(finding_id, payload)
    except VulnerabilityNotFound as error:
        raise ApiError("vulnerability_not_found", str(error), 404) from None
    except VulnerabilityWorkflowError as error:
        raise ApiError("vulnerability_transition_rejected", str(error), 409) from None


@router.post(
    "/findings/{finding_id}/decision", response_model=VulnerabilityMutationView, status_code=201
)
def decide(
    finding_id: UUID, payload: VulnerabilityDecisionRequest, request: Request
) -> VulnerabilityMutationView:
    _require_operator_control(request)
    return _call(lambda: _service(request).decide(finding_id, payload))


@router.post(
    "/findings/{finding_id}/changes", response_model=VulnerabilityMutationView, status_code=201
)
def start_change(
    finding_id: UUID, payload: VulnerabilityChangeRequest, request: Request
) -> VulnerabilityMutationView:
    _require_operator_control(request)
    return _call(lambda: _service(request).start_change(finding_id, payload))


@router.post(
    "/findings/{finding_id}/implementation",
    response_model=VulnerabilityMutationView,
    status_code=201,
)
def complete_change(
    finding_id: UUID, payload: VulnerabilityImplementationRequest, request: Request
) -> VulnerabilityMutationView:
    _require_operator_control(request)
    return _call(lambda: _service(request).complete_change(finding_id, payload))


@router.post(
    "/findings/{finding_id}/verification", response_model=VulnerabilityMutationView, status_code=201
)
def verify(
    finding_id: UUID, payload: VulnerabilityVerificationRequest, request: Request
) -> VulnerabilityMutationView:
    _require_operator_control(request)
    return _call(lambda: _service(request).verify(finding_id, payload))
