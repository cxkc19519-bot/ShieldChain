from importlib.util import find_spec


def test_foundation_and_registration_port_packages_exist() -> None:
    assert find_spec("saga") is not None
    assert find_spec("saga.domain") is not None
    assert find_spec("saga.crypto") is not None
    assert find_spec("saga.ports") is not None
