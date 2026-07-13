from fastapi import FastAPI

from shieldchain.api.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(health_router, prefix="/api/v1")
    return app
