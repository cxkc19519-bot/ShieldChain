import asyncio
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy.engine import Engine
from starlette.exceptions import HTTPException

from shieldchain.agents.trajectory import CollaborationTrajectoryQuery
from shieldchain.api.agents import router as agents_router
from shieldchain.api.health import router as health_router
from shieldchain.api.incidents import router as incidents_router
from shieldchain.api.knowledge import router as knowledge_router
from shieldchain.api.tools import router as tools_router
from shieldchain.core.config import Settings, get_settings
from shieldchain.core.errors import (
    ApiError,
    api_error_handler,
    http_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from shieldchain.core.logging import configure_logging
from shieldchain.core.request_id import RequestIdMiddleware
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.background import InvestigationRunner
from shieldchain.incidents.ports import IncidentRepository
from shieldchain.incidents.queries import IncidentQueryService
from shieldchain.incidents.repositories import SqlAlchemyIncidentRepository
from shieldchain.incidents.scenario import seed_phishing_scenario
from shieldchain.incidents.tools import SimulatedFirewall
from shieldchain.incidents.workflow import InvestigationWorkflow
from shieldchain.rag.api_service import KnowledgeApiService, UnconfiguredKnowledgeApiService
from shieldchain.tools.api_service import TrustedToolApiService


def create_app(
    *,
    database_engine: Engine | None = None,
    settings: Settings | None = None,
    agent_trajectory_query: CollaborationTrajectoryQuery | None = None,
    incident_repository: IncidentRepository | None = None,
    investigation_runner: InvestigationRunner | None = None,
    incident_query_service: IncidentQueryService | None = None,
    knowledge_api_service: KnowledgeApiService | None = None,
    trusted_tool_api_service: TrustedToolApiService | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.environment)
    owns_engine = database_engine is None
    engine = database_engine or create_engine_from_url(settings.database_url)
    session_factory = create_session_factory(engine)
    repository = incident_repository or SqlAlchemyIncidentRepository(seed_phishing_scenario)
    query_service = incident_query_service or IncidentQueryService(session_factory)
    workflow = InvestigationWorkflow(
        repository,
        SimulatedFirewall(),
        lambda: datetime.now(UTC),
        time.sleep,
        settings.simulation_step_delay_ms / 1000,
    )
    runner = investigation_runner or InvestigationRunner(
        workflow,
        repository,
        session_factory,
        shutdown_timeout_seconds=settings.simulation_shutdown_timeout_seconds,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            await asyncio.to_thread(runner.recover_interrupted)
            yield
        finally:
            await runner.shutdown()
            if owns_engine:
                engine.dispose()

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.database_engine = engine
    app.state.agent_trajectory_query = agent_trajectory_query or CollaborationTrajectoryQuery(
        session_factory
    )
    app.include_router(agents_router, prefix="/api/v1")
    app.state.incident_session_factory = session_factory
    app.state.incident_repository = repository
    app.state.incident_query_service = query_service
    app.state.investigation_runner = runner
    app.state.knowledge_api_service = knowledge_api_service or UnconfiguredKnowledgeApiService()
    app.state.trusted_tool_api_service = trusted_tool_api_service or TrustedToolApiService(
        session_factory
    )
    app.state.rag_demo_tenant_id = settings.rag_demo_tenant_id
    app.state.rag_demo_principal_id = settings.rag_demo_principal_id
    app.add_middleware(RequestIdMiddleware)
    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(knowledge_router, prefix="/api/v1")
    app.include_router(tools_router, prefix="/api/v1")
    return app
