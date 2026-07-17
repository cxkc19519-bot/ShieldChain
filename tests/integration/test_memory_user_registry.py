from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from saga.adapters.persistence.memory import InMemoryUserRegistry
from saga.domain import UserId, UserRegistration
from saga.domain.users import StoredPasswordRecord
from saga.ports.transactions import UserCreateOutcome


def _registration(name: str = "alice") -> UserRegistration:
    return UserRegistration(
        user_id=UserId(name),
        password_record=StoredPasswordRecord(1, 2**15, 8, 1, 32, b"s" * 16, b"v" * 32),
        certificate_der=b"certificate",
    )


def test_memory_registry_concurrent_duplicate_has_exactly_one_winner() -> None:
    registry = InMemoryUserRegistry()
    registration = _registration()
    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(lambda _: registry.create_if_absent(registration), range(64)))
    assert outcomes.count(UserCreateOutcome.CREATED) == 1
    assert outcomes.count(UserCreateOutcome.USER_ID_CONFLICT) == 63
    assert registry.get(registration.user_id) == registration


def test_memory_registry_returns_immutable_registration_record() -> None:
    registry = InMemoryUserRegistry()
    registration = _registration()
    assert registry.create_if_absent(registration) is UserCreateOutcome.CREATED
    stored = registry.get(registration.user_id)
    assert stored == registration
    assert stored is registration
    try:
        assert stored is not None
        stored.certificate_der = b"replace"  # type: ignore[misc]
    except (AttributeError, TypeError):
        pass
    else:
        raise AssertionError("registry returned a writable registration")
    assert registry.get(registration.user_id) == registration
