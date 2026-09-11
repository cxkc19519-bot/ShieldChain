import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PYTHON = Path(sys.executable)
NEW_INDEXES = {
    "ix_investigation_run_incident_created",
    "ix_investigation_run_simulation_created",
    "ix_trusted_tool_call_tenant_run_created",
}


def _alembic(database: Path, *arguments: str) -> None:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    result = subprocess.run(
        [str(PYTHON), "-m", "alembic", *arguments],
        cwd=ROOT / "backend",
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _indexes(database: Path) -> set[str]:
    with sqlite3.connect(database) as connection:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }


def test_phase8_query_indexes_upgrade_downgrade_and_upgrade(tmp_path: Path) -> None:
    database = tmp_path / "indexes.db"
    _alembic(database, "upgrade", "head")
    upgraded = _indexes(database)
    assert NEW_INDEXES <= upgraded
    assert "ix_trusted_tool_call_tenant_run" not in upgraded

    _alembic(database, "downgrade", "20260723_05")
    downgraded = _indexes(database)
    assert not NEW_INDEXES & downgraded
    assert "ix_trusted_tool_call_tenant_run" in downgraded

    _alembic(database, "upgrade", "head")
    assert NEW_INDEXES <= _indexes(database)
