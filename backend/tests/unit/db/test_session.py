from concurrent.futures import ThreadPoolExecutor

import structlog
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError

from shieldchain.core.logging import configure_logging
from shieldchain.db.session import (
    check_database,
    create_engine_from_url,
    create_session_factory,
)


def test_in_memory_sqlite_supports_cross_thread_connection() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")

    def select_one(connection: Connection) -> int:
        return connection.execute(text("SELECT 1")).scalar_one()

    with engine.connect() as connection, ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(select_one, connection).result() == 1


def test_session_factory_creates_usable_session() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    session_factory = create_session_factory(engine)

    with session_factory() as session:
        assert session.execute(text("SELECT 1")).scalar_one() == 1


def test_database_check_returns_true_for_successful_probe() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")

    assert check_database(engine) is True


def test_database_check_returns_false_and_logs_only_fixed_event(capsys) -> None:
    configure_logging("test")
    secret_url = "sqlite:///secret-database-name.db"
    secret_detail = "driver leaked secret detail"
    engine = create_engine(secret_url)
    structlog.contextvars.clear_contextvars()

    def fail_connect():
        raise OperationalError("SELECT 1", {}, Exception(secret_detail))

    engine.connect = fail_connect  # type: ignore[method-assign]

    assert check_database(engine) is False

    output = capsys.readouterr().out
    assert "database_check_failed" in output
    assert secret_url not in output
    assert "secret-database-name" not in output
    assert secret_detail not in output
    assert "SELECT 1" not in output
