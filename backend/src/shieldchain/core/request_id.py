import re
from time import perf_counter
from uuid import uuid4

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from shieldchain.core.errors import REQUEST_ID_HEADER

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
logger = structlog.get_logger(__name__)


def _select_request_id(value: str | None) -> str:
    if value is not None and REQUEST_ID_PATTERN.fullmatch(value):
        return value
    return uuid4().hex


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        structlog.contextvars.clear_contextvars()
        request_id = _select_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id
        structlog.contextvars.bind_contextvars(request_id=request_id)
        started_at = perf_counter()

        try:
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round((perf_counter() - started_at) * 1000, 3),
            )
            return response
        except Exception as error:
            logger.error(
                "request_failed",
                method=request.method,
                path=request.url.path,
                status=500,
                duration_ms=round((perf_counter() - started_at) * 1000, 3),
                error_type=type(error).__name__,
            )
            raise
        finally:
            structlog.contextvars.clear_contextvars()
