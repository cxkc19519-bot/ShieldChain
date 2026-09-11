from typing import cast
from uuid import UUID

from fastapi import APIRouter, Query, Request, status
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.assistant.service import GroundedAssistantService
from shieldchain.core.errors import ApiError
from shieldchain.incidents.ports import (
    IncidentNotFound,
    IncidentRepository,
    InvalidInvestigationState,
    InvestigationNotFound,
)
from shieldchain.incidents.queries import IncidentQueryService
from shieldchain.incidents.schemas import (
    AuditResponse,
    HistoricalReportListResponse,
    IncidentResponse,
    InvestigationResponse,
)

router = APIRouter(tags=["incidents"])


def _repository(request: Request) -> IncidentRepository:
    return cast(IncidentRepository, request.app.state.incident_repository)


def _factory(request: Request) -> sessionmaker[Session]:
    return cast(sessionmaker[Session], request.app.state.incident_session_factory)


def _queries(request: Request) -> IncidentQueryService:
    return cast(IncidentQueryService, request.app.state.incident_query_service)


def _assistant(request: Request) -> GroundedAssistantService:
    return cast(GroundedAssistantService, request.app.state.grounded_assistant_service)


def _public_error(error: Exception) -> ApiError:
    if isinstance(error, InvestigationNotFound):
        return ApiError("investigation_not_found", "Investigation not found", 404)
    if isinstance(error, IncidentNotFound):
        return ApiError("incident_not_found", "Incident not found", 404)
    if isinstance(error, InvalidInvestigationState):
        return ApiError(
            "invalid_investigation_state",
            "Investigation state does not allow this operation",
            409,
        )
    raise error


@router.get("/reports/history", response_model=HistoricalReportListResponse)
def list_historical_reports(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
) -> HistoricalReportListResponse:
    return _queries(request).historical_reports(limit)

@router.delete("/reports/history/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_historical_report(run_id: UUID, request: Request) -> None:
    try:
        report = _queries(request).investigation(run_id)
        _assistant(request).remove_historical_report(report.run_tracking_id)
        with _factory(request).begin() as session:
            _repository(request).delete_historical_run(session, run_id)
    except Exception as error:
        raise _public_error(error) from None

@router.get("/investigations/{run_id}", response_model=InvestigationResponse)
def get_investigation(run_id: UUID, request: Request) -> InvestigationResponse:
    try:
        return _queries(request).investigation(run_id)
    except Exception as error:
        raise _public_error(error) from None


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: UUID, request: Request) -> IncidentResponse:
    try:
        return _queries(request).incident(incident_id)
    except Exception as error:
        raise _public_error(error) from None


@router.get("/incidents/{incident_id}/audit", response_model=AuditResponse)
def get_audit(incident_id: UUID, request: Request) -> AuditResponse:
    try:
        return _queries(request).audit(incident_id)
    except Exception as error:
        raise _public_error(error) from None
