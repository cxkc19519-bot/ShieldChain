import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from shieldchain.core.version import EXPECTED_SCHEMA_REVISION, SERVICE_VERSION
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


def _stamp_head(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": EXPECTED_SCHEMA_REVISION},
        )


def test_version_is_public_stable_and_contains_no_host_metadata(client: TestClient) -> None:
    response = client.get("/api/v1/health/version")
    assert response.status_code == 200
    assert response.json() == {
        "service": "shieldchain",
        "version": SERVICE_VERSION,
        "schema_revision": EXPECTED_SCHEMA_REVISION,
    }
    assert set(response.json()) == {"service", "version", "schema_revision"}


def test_ready_health_check_returns_exact_contract(tmp_path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'ready.db'}")
    _stamp_head(engine)
    with TestClient(create_app(database_engine=engine)) as ready_client:
        response = ready_client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ok", "migrations": "current", "lifecycle": "accepting"},
    }


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
        "checks": {
            "database": "failed",
            "migrations": "unavailable",
            "lifecycle": "accepting",
        },
    }


@pytest.mark.parametrize(
    ("revision", "expected"),
    [(None, "unavailable"), ("20260723_05", "outdated")],
)
def test_ready_fails_closed_for_missing_or_outdated_migration(
    tmp_path, revision: str | None, expected: str
) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'outdated.db'}")
    if revision is not None:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": revision},
            )
    with TestClient(create_app(database_engine=engine)) as client:
        response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {
        "database": "ok",
        "migrations": expected,
        "lifecycle": "accepting",
    }


def test_startup_propagates_database_connection_failure() -> None:
    engine = create_engine("sqlite:///:memory:")

    def fail_connect():
        raise OperationalError("SELECT 1", {}, Exception("controlled failure"))

    engine.connect = fail_connect  # type: ignore[method-assign]

    with pytest.raises(OperationalError):
        with TestClient(create_app(database_engine=engine)):
            pass
