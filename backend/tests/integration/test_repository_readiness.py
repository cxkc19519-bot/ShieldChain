import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from shieldchain.core.config import get_settings
from shieldchain.main import create_app


def test_fresh_checkout_requires_migration_before_database_becomes_ready(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[3]
    placeholder = repository_root / "data" / ".gitkeep"

    tracked = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repository_root.as_posix()}",
            "ls-files",
            "--error-unmatch",
            "data/.gitkeep",
        ],
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tracked.returncode == 0
    assert placeholder.is_file()

    clone_root = tmp_path / "fresh-checkout"
    clone_data = clone_root / "data"
    clone_data.mkdir(parents=True)
    (clone_data / ".gitkeep").write_bytes(placeholder.read_bytes())
    database_path = clone_data / "shieldchain.db"
    assert not database_path.exists()

    monkeypatch.chdir(clone_root)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    get_settings.cache_clear()
    app = create_app()
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health/ready")
    finally:
        app.state.database_engine.dispose()
        get_settings.cache_clear()

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "ok",
            "migrations": "unavailable",
            "lifecycle": "accepting",
        },
    }
    assert database_path.is_file()

    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
    migrated = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=repository_root / "backend",
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert migrated.returncode == 0, migrated.stdout + migrated.stderr

    get_settings.cache_clear()
    migrated_app = create_app()
    try:
        with TestClient(migrated_app) as client:
            ready = client.get("/api/v1/health/ready")
    finally:
        migrated_app.state.database_engine.dispose()
        get_settings.cache_clear()
    assert ready.status_code == 200
    assert ready.json()["checks"]["migrations"] == "current"
