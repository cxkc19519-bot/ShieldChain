import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from shieldchain.db.session import create_engine_from_url
from shieldchain.main import create_app


class NoopRunner:
    def recover_interrupted(self) -> int:
        return 0

    async def shutdown(self) -> None:
        return None


def test_live_health_check_returns_exact_contract(client: TestClient) -> None:
    response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_health_check_returns_exact_contract(client: TestClient) -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    with TestClient(create_app(database_engine=engine)) as ready_client:
        response = ready_client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok"}}


def test_ready_health_check_returns_exact_failure_contract() -> None:
    engine = create_engine("sqlite:///:memory:")

    def fail_connect():
        raise OperationalError("SELECT 1", {}, Exception("controlled failure"))

    engine.connect = fail_connect  # type: ignore[method-assign]

    with TestClient(
        create_app(database_engine=engine, investigation_runner=NoopRunner())
    ) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"database": "failed"},
    }


def test_startup_propagates_database_connection_failure() -> None:
    engine = create_engine("sqlite:///:memory:")

    def fail_connect():
        raise OperationalError("SELECT 1", {}, Exception("controlled failure"))

    engine.connect = fail_connect  # type: ignore[method-assign]

    with pytest.raises(OperationalError):
        with TestClient(create_app(database_engine=engine)):
            pass
