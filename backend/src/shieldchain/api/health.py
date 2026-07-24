from typing import Literal, cast

from fastapi import APIRouter, Request, Response, status
from sqlalchemy.engine import Engine

from shieldchain.core.version import EXPECTED_SCHEMA_REVISION, SERVICE_NAME, SERVICE_VERSION
from shieldchain.db.session import check_database, database_schema_revision

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/version")
def service_version() -> dict[str, str]:
    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "schema_revision": EXPECTED_SCHEMA_REVISION,
    }


@router.get("/ready")
def ready(request: Request, response: Response) -> dict[str, object]:
    engine = cast(Engine, request.app.state.database_engine)
    database_ready = check_database(engine)
    accepting = bool(getattr(request.app.state, "accepting_requests", False))
    revision = database_schema_revision(engine) if database_ready else None
    migrations_current = revision == EXPECTED_SCHEMA_REVISION
    ready_now = database_ready and migrations_current and accepting
    readiness_status: Literal["ready", "not_ready"] = (
        "ready" if ready_now else "not_ready"
    )
    database_status: Literal["ok", "failed"] = "ok" if database_ready else "failed"
    migration_status: Literal["current", "outdated", "unavailable"] = (
        "current"
        if migrations_current
        else "outdated"
        if database_ready and revision is not None
        else "unavailable"
    )
    lifecycle_status: Literal["accepting", "stopping"] = (
        "accepting" if accepting else "stopping"
    )
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": readiness_status,
        "checks": {
            "database": database_status,
            "migrations": migration_status,
            "lifecycle": lifecycle_status,
        },
    }
