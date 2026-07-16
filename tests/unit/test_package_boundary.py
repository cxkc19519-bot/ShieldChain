from importlib.util import find_spec
from pathlib import Path


def test_phase_one_package_exists_without_forbidden_layers() -> None:
    assert find_spec("saga") is not None
    assert find_spec("saga.domain") is not None
    assert find_spec("saga.crypto") is not None
    for forbidden in ("protocols", "ports", "adapters"):
        assert not Path("src", "saga", forbidden).exists()
