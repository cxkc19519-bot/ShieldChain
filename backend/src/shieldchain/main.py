from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException

from shieldchain.api.health import router as health_router
from shieldchain.core.config import get_settings
from shieldchain.core.errors import (
    ApiError,
    api_error_handler,
    http_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from shieldchain.core.logging import configure_logging
from shieldchain.core.request_id import RequestIdMiddleware


def create_app() -> FastAPI:
    configure_logging(get_settings().environment)
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)
    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
    app.include_router(health_router, prefix="/api/v1")
    return app
