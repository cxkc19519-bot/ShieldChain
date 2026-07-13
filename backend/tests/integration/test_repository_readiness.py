import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from shieldchain.core.config import get_settings
from shieldchain.main import create_app


def test_fresh_checkout_default_sqlite_database_becomes_ready(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[3]
    placeholder = repository_root / "data" / ".gitkeep"

    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "data/.gitkeep"],
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

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok"}}
    assert database_path.is_file()
