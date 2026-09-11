"""Fail-closed HTTP size and response-header boundaries."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from shieldchain.core.errors import REQUEST_ID_HEADER

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def _boundary_error(request: Request, code: str, message: str, status_code: int) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unavailable")
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={REQUEST_ID_HEADER: request_id},
    )


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject invalid or excessive declared request bodies before endpoint parsing."""

    def __init__(self, app, *, maximum_bytes: int) -> None:
        super().__init__(app)
        if not isinstance(maximum_bytes, int) or isinstance(maximum_bytes, bool):
            raise TypeError("maximum_bytes must be an integer")
        if not 1 <= maximum_bytes <= 100 * 1024 * 1024:
            raise ValueError("maximum_bytes must be between 1 and 104857600")
        self._maximum_bytes = maximum_bytes

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                return _boundary_error(
                    request, "invalid_content_length", "Content-Length is invalid", 400
                )
            if length < 0:
                return _boundary_error(
                    request, "invalid_content_length", "Content-Length is invalid", 400
                )
            if length > self._maximum_bytes:
                return _boundary_error(
                    request, "request_too_large", "Request exceeds configured limit", 413
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply deterministic API security headers, including HSTS only in production."""

    def __init__(self, app, *, production: bool) -> None:
        super().__init__(app)
        self._production = production

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        if self._production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
