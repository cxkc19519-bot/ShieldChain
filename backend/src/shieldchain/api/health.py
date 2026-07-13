from typing import Literal, cast

from fastapi import APIRouter, Request, Response, status
from sqlalchemy.engine import Engine

from shieldchain.db.session import check_database

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(request: Request, response: Response) -> dict[str, object]:
    engine = cast(Engine, request.app.state.database_engine)
    database_ready = check_database(engine)
    readiness_status: Literal["ready", "not_ready"] = (
        "ready" if database_ready else "not_ready"
    )
    database_status: Literal["ok", "failed"] = "ok" if database_ready else "failed"
    if not database_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": readiness_status, "checks": {"database": database_status}}
