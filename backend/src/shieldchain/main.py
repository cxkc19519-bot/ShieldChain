from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy.engine import Engine
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
from shieldchain.db.session import create_engine_from_url


def create_app(*, database_engine: Engine | None = None) -> FastAPI:
    settings = get_settings()
    configure_logging(settings.environment)
    app = FastAPI()
    app.state.database_engine = database_engine or create_engine_from_url(settings.database_url)
    app.add_middleware(RequestIdMiddleware)
    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
    app.include_router(health_router, prefix="/api/v1")
    return app
