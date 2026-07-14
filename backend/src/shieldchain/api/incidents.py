import asyncio
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Body, Request, status
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.incidents.background import (
    InvestigationRunner,
    InvestigationRunnerUnavailable,
)
from shieldchain.incidents.domain import InvestigationStatus, RunMode
from shieldchain.incidents.ports import (
    ActiveInvestigationExists,
    IncidentNotFound,
    IncidentRepository,
    InvalidInvestigationState,
    InvestigationNotFound,
    SimulationNotFound,
)
from shieldchain.incidents.queries import IncidentQueryService
from shieldchain.incidents.schemas import (
    AuditResponse,
    IncidentResponse,
    IncidentView,
    InvestigationResponse,
    ResetSimulationRequest,
    ResetSimulationResponse,
    SimulationView,
    StartInvestigationRequest,
)

router = APIRouter(tags=["incidents"])


def _request_id(request: Request) -> str:
    return cast(str, request.state.request_id)


def _repository(request: Request) -> IncidentRepository:
    return cast(IncidentRepository, request.app.state.incident_repository)


def _factory(request: Request) -> sessionmaker[Session]:
    return cast(sessionmaker[Session], request.app.state.incident_session_factory)


def _queries(request: Request) -> IncidentQueryService:
    return cast(IncidentQueryService, request.app.state.incident_query_service)


def _runner(request: Request) -> InvestigationRunner:
    return cast(InvestigationRunner, request.app.state.investigation_runner)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _public_error(error: Exception) -> ApiError:
    if isinstance(error, SimulationNotFound):
        return ApiError("simulation_not_found", "Simulation not found", 404)
    if isinstance(error, InvestigationNotFound):
        return ApiError("investigation_not_found", "Investigation not found", 404)
    if isinstance(error, IncidentNotFound):
        return ApiError("incident_not_found", "Incident not found", 404)
    if isinstance(error, ActiveInvestigationExists):
        return ApiError(
            "investigation_already_running", "An investigation is already running", 409
        )
    if isinstance(error, InvalidInvestigationState):
        return ApiError(
            "invalid_investigation_state",
            "Investigation state does not allow this operation",
            409,
        )
    if isinstance(error, InvestigationRunnerUnavailable):
        return ApiError(
            "investigation_runner_unavailable", "Investigation runner is unavailable", 503
        )
    raise error


@router.post(
    "/simulations/phishing/reset",
    status_code=status.HTTP_201_CREATED,
    response_model=ResetSimulationResponse,
)
def reset_phishing(
    request: Request,
    _payload: ResetSimulationRequest | None = Body(default=None),
) -> ResetSimulationResponse:
    repository = _repository(request)
    try:
        with _factory(request).begin() as session:
            state = repository.reset_phishing_scenario(
                session, now=datetime.now(UTC), request_id=_request_id(request)
            )
    except Exception as error:
        raise _public_error(error) from None
    incident = _queries(request).incident(state.incident_id).incident
    return ResetSimulationResponse(
        simulation=SimulationView(
            id=state.simulation_id,
            generation=state.generation,
            environment=state.environment,
            connection_status=state.connection_status,
            firewall_status=state.firewall_status,
            fail_block_consumed=state.fail_block_consumed,
        ),
        incident=IncidentView.model_validate(incident.model_dump()),
    )


@router.post(
    "/investigations",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvestigationResponse,
)
async def start_investigation(
    payload: StartInvestigationRequest, request: Request
) -> InvestigationResponse:
    if (
        _settings(request).environment.casefold() == "production"
        and payload.mode == "fail_block_once"
    ):
        raise ApiError(
            "simulation_mode_forbidden",
            "Simulation failure mode is disabled in production",
            403,
        )
    request_id = _request_id(request)
    repository = _repository(request)
    queries = _queries(request)
    factory = _factory(request)

    def create_or_reuse() -> tuple[InvestigationResponse, bool]:
        latest = queries.latest_run_for_simulation(payload.simulation_instance_id)
        if latest is not None and latest.status == InvestigationStatus.CLOSED.value:
            return queries.investigation(latest.run_id), False
        with factory.begin() as session:
            run = repository.create_run(
                session,
                simulation_id=payload.simulation_instance_id,
                mode=RunMode(payload.mode),
                request_id=request_id,
                now=datetime.now(UTC),
            )
        return queries.investigation(run.id), True

    try:
        response, should_start = await asyncio.to_thread(create_or_reuse)
        if should_start:
            _runner(request).start(
                response.run_id,
                request_id,
                payload.mode == "fail_block_once",
            )
        return response
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
