from pathlib import Path


def test_phase_one_has_no_runtime_or_protocol_layers() -> None:
    forbidden = ("protocols", "ports", "adapters", "http", "persistence")
    tracked = {path.as_posix() for path in Path("src/saga").rglob("*.py")}
    assert not any(f"/{name}/" in f"/{path}" for name in forbidden for path in tracked)
