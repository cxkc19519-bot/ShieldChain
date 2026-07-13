from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

REQUEST_ID_HEADER = "X-Request-ID"


class ApiError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _error_response(
    *,
    code: str,
    message: str,
    status_code: int,
    request_id: str,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        },
        headers={REQUEST_ID_HEADER: request_id},
    )


async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
    return _error_response(
        code=error.code,
        message=error.message,
        status_code=error.status_code,
        request_id=request.state.request_id,
    )


async def http_error_handler(request: Request, error: HTTPException) -> JSONResponse:
    message = error.detail if isinstance(error.detail, str) else "Request failed"
    return _error_response(
        code="http_error",
        message=message,
        status_code=error.status_code,
        request_id=request.state.request_id,
    )


async def validation_error_handler(
    request: Request,
    _error: RequestValidationError,
) -> JSONResponse:
    return _error_response(
        code="validation_error",
        message="Request validation failed",
        status_code=422,
        request_id=request.state.request_id,
    )


async def unhandled_error_handler(request: Request, _error: Exception) -> JSONResponse:
    return _error_response(
        code="internal_error",
        message="Internal server error",
        status_code=500,
        request_id=request.state.request_id,
    )
