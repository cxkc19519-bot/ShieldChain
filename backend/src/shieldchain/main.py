from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy.engine import Engine
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from shieldchain.agents.trajectory import CollaborationTrajectoryQuery
from shieldchain.api.agents import router as agents_router
from shieldchain.api.health import router as health_router
from shieldchain.api.incidents import router as incidents_router
from shieldchain.api.knowledge import router as knowledge_router
from shieldchain.api.mcp import router as mcp_router
from shieldchain.api.operations import router as operations_router
from shieldchain.api.react import router as react_router
from shieldchain.api.tools import router as tools_router
from shieldchain.api.wazuh import router as wazuh_router
from shieldchain.assistant.api import router as assistant_router
from shieldchain.assistant.service import GroundedAssistantService
from shieldchain.assistant.store import LocalConversationStore
from shieldchain.core.config import Settings, get_settings
from shieldchain.core.errors import (
    ApiError,
    api_error_handler,
    http_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from shieldchain.core.http_security import RequestSizeLimitMiddleware, SecurityHeadersMiddleware
from shieldchain.core.logging import configure_logging
from shieldchain.core.request_id import RequestIdMiddleware
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.ports import IncidentRepository
from shieldchain.incidents.queries import IncidentQueryService
from shieldchain.incidents.repositories import SqlAlchemyIncidentRepository
from shieldchain.incidents.scenario import seed_phishing_scenario
from shieldchain.mcp_auth import build_mcp_auth_runtime
from shieldchain.mcp_remote.discovery import McpDiscoveryService
from shieldchain.mcp_remote.peer_config import load_mcp_remote_config
from shieldchain.mcp_remote.persistence import McpSnapshotStore
from shieldchain.mcp_remote.runtime import McpRemoteRuntime
from shieldchain.mcp_server import create_mcp_http_app, create_mcp_server
from shieldchain.operations.audit import AgentToolAuditStore
from shieldchain.operations.service import OperationsReportStore, SecurityOperationsReportAgent
from shieldchain.qwen_experience.api import router as qwen_experience_router
from shieldchain.qwen_experience.service import QwenExperienceService
from shieldchain.rag.api_service import KnowledgeApiService
from shieldchain.rag.local_service import LocalKnowledgeService
from shieldchain.react.api_service import ReactApiService
from shieldchain.tools.api_service import TrustedToolApiService
from shieldchain.wazuh.service import WazuhAlertService


def create_app(
    *,
    database_engine: Engine | None = None,
    settings: Settings | None = None,
    agent_trajectory_query: CollaborationTrajectoryQuery | None = None,
    incident_repository: IncidentRepository | None = None,
    incident_query_service: IncidentQueryService | None = None,
    knowledge_api_service: KnowledgeApiService | None = None,
    react_api_service: ReactApiService | None = None,
    trusted_tool_api_service: TrustedToolApiService | None = None,
    qwen_experience_service: QwenExperienceService | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.environment)
    owns_engine = database_engine is None
    engine = database_engine or create_engine_from_url(settings.database_url)
    session_factory = create_session_factory(engine)
    repository = incident_repository or SqlAlchemyIncidentRepository(seed_phishing_scenario)
    query_service = incident_query_service or IncidentQueryService(session_factory)
    knowledge_service = knowledge_api_service or LocalKnowledgeService(settings.rag_content_root)
    agent_tool_audit_store = AgentToolAuditStore(session_factory)
    mcp_remote_config = (
        load_mcp_remote_config(settings.mcp_remote_config_path)
        if settings.mcp_remote_config_path is not None
        else None
    )
    mcp_snapshot_store = McpSnapshotStore(session_factory)
    mcp_remote_discovery = (
        McpDiscoveryService(mcp_snapshot_store, settings) if mcp_remote_config is not None else None
    )
    mcp_remote_runtime = (
        McpRemoteRuntime(mcp_snapshot_store, mcp_remote_config, settings)
        if mcp_remote_config is not None
        else None
    )
    mcp_server = (
        create_mcp_server(
            session_factory,
            tenant_id=settings.rag_demo_tenant_id,
            principal_id=settings.rag_demo_principal_id,
            audit_store=agent_tool_audit_store,
            auth_runtime=build_mcp_auth_runtime(settings),
        )
        if settings.mcp_server_enabled
        else None
    )
    mcp_http_app = create_mcp_http_app(mcp_server, settings) if mcp_server is not None else None
    trusted_tools = trusted_tool_api_service or TrustedToolApiService(session_factory)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        agent_tool_audit_store.recover_interrupted(now=datetime.now(UTC))
        recover_safety = getattr(trusted_tools, "recover_safety_loops", None)
        if callable(recover_safety):
            recover_safety(
                tenant_id=settings.rag_demo_tenant_id,
                now=datetime.now(UTC),
            )
        if mcp_remote_discovery is not None and mcp_remote_config is not None:
            _app.state.mcp_remote_discovery_outcomes = await mcp_remote_discovery.refresh_enabled(
                mcp_remote_config
            )
        _app.state.accepting_requests = True
        try:
            if mcp_server is None:
                yield
            else:
                async with mcp_server.session_manager.run():
                    yield
        finally:
            _app.state.accepting_requests = False
            if owns_engine:
                engine.dispose()

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.mcp_server = mcp_server
    app.state.mcp_remote_discovery = mcp_remote_discovery
    app.state.mcp_remote_runtime = mcp_remote_runtime
    app.state.mcp_remote_discovery_outcomes = ()
    app.state.agent_tool_audit_store = agent_tool_audit_store
    app.state.qwen_experience_service = qwen_experience_service or QwenExperienceService(settings)
    app.state.database_engine = engine
    app.state.accepting_requests = False
    app.state.agent_trajectory_query = agent_trajectory_query or CollaborationTrajectoryQuery(
        session_factory
    )
    app.include_router(agents_router, prefix="/api/v1")
    app.include_router(assistant_router, prefix="/api/v1")
    app.include_router(qwen_experience_router, prefix="/api/v1")
    app.state.incident_session_factory = session_factory
    app.state.incident_repository = repository
    app.state.incident_query_service = query_service
    app.state.knowledge_api_service = knowledge_service
    app.state.grounded_assistant_service = GroundedAssistantService(
        knowledge_service,
        query_service,
        settings=settings,
        tenant_id=settings.rag_demo_tenant_id,
        principal_id=settings.rag_demo_principal_id,
        store=LocalConversationStore(settings.assistant_data_root),
    )
    app.state.trusted_tool_api_service = trusted_tools
    app.state.rag_demo_tenant_id = settings.rag_demo_tenant_id
    app.state.react_api_service = react_api_service or ReactApiService(session_factory)
    app.state.wazuh_alert_service = WazuhAlertService()
    app.state.security_operations_report_agent = SecurityOperationsReportAgent(
        session_factory,
        settings=settings,
        tenant_id=settings.rag_demo_tenant_id,
        store=OperationsReportStore(settings.assistant_data_root),
        knowledge=knowledge_service,
        principal_id=settings.rag_demo_principal_id,
        audit_store=agent_tool_audit_store,
        remote_runtime=mcp_remote_runtime,
    )
    app.state.rag_demo_principal_id = settings.rag_demo_principal_id
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.http_allowed_origins),
        allow_credentials=False,
        allow_methods=["DELETE", "GET", "POST"],
        allow_headers=["Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.http_allowed_hosts),
        www_redirect=False,
    )
    app.add_middleware(
        RequestSizeLimitMiddleware,
        maximum_bytes=settings.http_max_request_bytes,
    )
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        SecurityHeadersMiddleware,
        production=settings.environment == "production",
    )
    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(knowledge_router, prefix="/api/v1")
    app.include_router(mcp_router, prefix="/api/v1")
    app.include_router(tools_router, prefix="/api/v1")
    app.include_router(react_router, prefix="/api/v1")
    app.include_router(wazuh_router, prefix="/api/v1")
    app.include_router(operations_router, prefix="/api/v1")
    if mcp_http_app is not None:
        app.mount("/", mcp_http_app)
    return app
