from __future__ import annotations

import logging
from dataclasses import fields

import pytest

import saga.protocols.user_registration as registration_module
from saga.adapters.persistence.memory import InMemoryUserRegistry
from saga.crypto.passwords import PasswordRecordError, hash_password
from saga.domain import (
    IdentityVerificationRejected,
    InvalidRegistrationInput,
    RegistrationPersistenceError,
    UserId,
    UserRegistrationExists,
)
from saga.domain.users import RegisterUserCommand
from saga.ports.transactions import UserCreateOutcome
from saga.protocols import UserRegistrationService
from tests.helpers.certificates import build_certificate_fixtures
from tests.helpers.registration import (
    DeterministicRandomSource,
    FixedClock,
    TrustedIdentityVerifier,
)

PASSWORD = "correct horse battery staple"
SALT = b"s" * 16


def _command() -> tuple[RegisterUserCommand, bytes, int]:
    fixtures = build_certificate_fixtures()
    return (
        RegisterUserCommand(UserId("alice"), PASSWORD, fixtures.user.der),
        fixtures.anchor_der,
        fixtures.now_ms,
    )


def _service(
    *,
    registry: InMemoryUserRegistry | object | None = None,
    identity_verifier: object | None = None,
    random_source: object | None = None,
) -> tuple[UserRegistrationService, object]:
    command, anchor_der, now_ms = _command()
    memory_registry = InMemoryUserRegistry() if registry is None else registry
    service = UserRegistrationService(
        identity_verifier=(
            TrustedIdentityVerifier(frozenset({command.user_id}))
            if identity_verifier is None
            else identity_verifier
        ),  # type: ignore[arg-type]
        user_registry=memory_registry,  # type: ignore[arg-type]
        clock=FixedClock(now_ms),
        random_source=(
            DeterministicRandomSource((SALT,)) if random_source is None else random_source
        ),  # type: ignore[arg-type]
        trust_anchor_der=anchor_der,
    )
    return service, memory_registry


def test_iv_b_success_returns_only_user_id_and_stores_redacted_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    command, _, _ = _command()
    service, registry = _service()
    assert isinstance(registry, InMemoryUserRegistry)
    caplog.set_level(logging.DEBUG)

    result = service.register(command)
    stored = registry.get(command.user_id)

    assert result.user_id == command.user_id
    assert tuple(field.name for field in fields(result)) == ("user_id",)
    assert stored is not None
    assert stored.user_id == command.user_id
    assert stored.certificate_der == command.certificate_der
    assert repr(stored.password_record) == "StoredPasswordRecord(version=1, redacted=True)"
    captured = caplog.text + repr(result) + repr(stored) + repr(stored.password_record)
    for secret in (
        PASSWORD,
        SALT.decode(),
        stored.password_record.verifier.hex(),
        command.certificate_der.hex(),
    ):
        assert secret not in captured


def test_identity_rejection_creates_no_record_and_never_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command, _, _ = _command()
    service, registry = _service(identity_verifier=TrustedIdentityVerifier(frozenset()))
    assert isinstance(registry, InMemoryUserRegistry)
    monkeypatch.setattr(
        registration_module,
        "hash_password",
        lambda *_args, **_kwargs: pytest.fail("password hashing must not run"),
    )

    with pytest.raises(IdentityVerificationRejected, match="^identity verification rejected$"):
        service.register(command)

    assert registry.get(command.user_id) is None


def test_identity_rejection_never_validates_certificate_or_creates_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command, _, _ = _command()
    service, registry = _service(identity_verifier=TrustedIdentityVerifier(frozenset()))
    assert isinstance(registry, InMemoryUserRegistry)
    monkeypatch.setattr(
        registration_module.certificates,
        "validated_leaf_public_key_bytes",
        lambda **_kwargs: pytest.fail("certificate validation must not run"),
    )

    with pytest.raises(IdentityVerificationRejected, match="^identity verification rejected$"):
        service.register(command)

    assert registry.get(command.user_id) is None


@pytest.mark.parametrize("certificate", [b"not-der", b""])
def test_invalid_or_mismatched_certificate_never_hashes_or_stores(
    certificate: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    command, _, _ = _command()
    malformed = (
        RegisterUserCommand(command.user_id, command.password, certificate) if certificate else None
    )
    if malformed is None:
        with pytest.raises(InvalidRegistrationInput):
            RegisterUserCommand(command.user_id, command.password, certificate)
        return
    service, registry = _service()
    assert isinstance(registry, InMemoryUserRegistry)
    monkeypatch.setattr(
        registration_module,
        "hash_password",
        lambda *_args, **_kwargs: pytest.fail("password hashing must not run"),
    )
    with pytest.raises(InvalidRegistrationInput, match="^invalid registration input$"):
        service.register(malformed)
    assert registry.get(command.user_id) is None


def test_mismatched_certificate_never_hashes_or_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    command, _, _ = _command()
    fixtures = build_certificate_fixtures()
    mismatched = RegisterUserCommand(command.user_id, command.password, fixtures.agent.der)
    service, registry = _service()
    assert isinstance(registry, InMemoryUserRegistry)
    monkeypatch.setattr(
        registration_module,
        "hash_password",
        lambda *_args, **_kwargs: pytest.fail("password hashing must not run"),
    )
    with pytest.raises(InvalidRegistrationInput, match="^invalid registration input$"):
        service.register(mismatched)
    assert registry.get(command.user_id) is None


def test_empty_password_is_rejected_before_a_registry_can_be_used() -> None:
    command, _, _ = _command()
    with pytest.raises(InvalidRegistrationInput, match="^invalid registration input$"):
        RegisterUserCommand(command.user_id, "", command.certificate_der)


def test_expired_certificate_never_hashes_or_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    command, anchor_der, _ = _command()
    registry = InMemoryUserRegistry()
    service = UserRegistrationService(
        identity_verifier=TrustedIdentityVerifier(frozenset({command.user_id})),
        user_registry=registry,
        clock=FixedClock(1_798_761_600_000),
        random_source=DeterministicRandomSource((SALT,)),
        trust_anchor_der=anchor_der,
    )
    monkeypatch.setattr(
        registration_module,
        "hash_password",
        lambda *_args, **_kwargs: pytest.fail("password hashing must not run"),
    )
    with pytest.raises(InvalidRegistrationInput):
        service.register(command)
    assert registry.get(command.user_id) is None


def test_deterministic_random_salt_creates_expected_password_record() -> None:
    command, _, _ = _command()
    service, registry = _service()
    assert isinstance(registry, InMemoryUserRegistry)
    service.register(command)
    stored = registry.get(command.user_id)
    assert stored is not None
    expected = hash_password(PASSWORD, salt=SALT)
    assert stored.password_record.salt == expected.salt
    assert stored.password_record.verifier == expected.verifier


def test_duplicate_user_is_a_stable_public_failure() -> None:
    command, _, _ = _command()
    service, registry = _service(random_source=DeterministicRandomSource((SALT, b"t" * 16)))
    assert isinstance(registry, InMemoryUserRegistry)
    service.register(command)
    with pytest.raises(UserRegistrationExists, match="^User registration already exists$"):
        service.register(command)
    assert registry.get(command.user_id) is not None


class FailingRegistry:
    def get(self, user_id: UserId) -> None:
        del user_id
        return None

    def create_if_absent(self, registration: object) -> UserCreateOutcome:
        del registration
        raise ValueError("backend secret detail")


def test_hash_and_registry_failures_are_normalized_without_secret_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command, _, _ = _command()
    service, _ = _service()
    original_hash_password = registration_module.hash_password
    monkeypatch.setattr(
        registration_module,
        "hash_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PasswordRecordError("backend secret detail")
        ),
    )
    with pytest.raises(
        InvalidRegistrationInput, match="^invalid registration input$"
    ) as hash_error:
        service.register(command)
    assert "detail" not in str(hash_error.value)

    monkeypatch.setattr(registration_module, "hash_password", original_hash_password)
    failing_service, _ = _service(registry=FailingRegistry())
    with pytest.raises(
        RegistrationPersistenceError, match="^registration persistence failed$"
    ) as storage_error:
        failing_service.register(command)
    assert "detail" not in str(storage_error.value)


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_system_exceptions_propagate_from_hashing(
    error: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    command, _, _ = _command()
    service, _ = _service()
    monkeypatch.setattr(
        registration_module,
        "hash_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(type(error)):
        service.register(command)
