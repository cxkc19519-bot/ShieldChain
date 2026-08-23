import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from shieldchain.core.config import get_settings


def _migrate(root: Path, database: Path, target: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    configuration = Config(str(root / "backend" / "alembic.ini"))
    command.upgrade(configuration, target) if target != "down" else command.downgrade(
        configuration, "20260823_02"
    )
    get_settings.cache_clear()


def test_mcp_snapshot_migration_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "mcp-snapshot-migration.db"

    _migrate(root, database, "20260823_02", monkeypatch)
    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "mcp_peer_snapshots",
            "mcp_tool_snapshots",
            "agent_run_mcp_snapshots",
        } <= tables

    _migrate(root, database, "down", monkeypatch)
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "mcp_peer_snapshots" not in tables
        assert "mcp_tool_snapshots" not in tables
        assert "agent_run_mcp_snapshots" not in tables

    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260823_05",
        )


def test_mcp_snapshot_downgrade_refuses_to_drop_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "mcp-snapshot-downgrade-guard.db"
    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO mcp_peer_snapshots "
            "(id,peer_id,endpoint,transport,network_policy,protocol_version,"
            "catalog_revision,status,error_code,discovered_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "00000000-0000-4000-8000-000000000001",
                "approved-peer",
                "https://security.example.test/mcp",
                "streamable_http",
                "public_https",
                "2026-07-28",
                "approved-v1",
                "accepted",
                None,
                "2026-08-23 12:00:00",
                "2026-08-23 13:00:00",
            ),
        )

    with pytest.raises(RuntimeError, match="snapshots exist"):
        _migrate(root, database, "down", monkeypatch)


def test_run_snapshot_binding_downgrade_refuses_to_drop_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "run-snapshot-binding-guard.db"
    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO agent_runs "
            "(id,tenant_id,principal_id,run_kind,status,goal,catalog_revision,revision,"
            "created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "00000000-0000-4000-8000-000000000101",
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
                "operations_report",
                "running",
                "test",
                "run-catalog",
                0,
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO mcp_peer_snapshots "
            "(id,peer_id,endpoint,transport,network_policy,protocol_version,"
            "catalog_revision,status,error_code,discovered_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "00000000-0000-4000-8000-000000000201",
                "approved-peer",
                "https://security.example.test/mcp",
                "streamable_http",
                "public_https",
                "2026-07-28",
                "peer-catalog",
                "accepted",
                None,
                "2026-08-23 12:00:00",
                "2026-08-23 13:00:00",
            ),
        )
        connection.execute(
            "INSERT INTO agent_run_mcp_snapshots "
            "(run_id,tenant_id,peer_id,peer_snapshot_id,catalog_revision) VALUES (?,?,?,?,?)",
            (
                "00000000-0000-4000-8000-000000000101",
                "00000000-0000-4000-8000-000000000001",
                "approved-peer",
                "00000000-0000-4000-8000-000000000201",
                "peer-catalog",
            ),
        )

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    configuration = Config(str(root / "backend" / "alembic.ini"))
    with pytest.raises(RuntimeError, match="agent runs reference"):
        command.downgrade(configuration, "20260823_03")
    get_settings.cache_clear()
