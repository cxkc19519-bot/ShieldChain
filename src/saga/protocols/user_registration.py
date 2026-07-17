"""Paper IV-B User Registration service."""

from __future__ import annotations

from saga.crypto import certificates
from saga.crypto.passwords import hash_password
from saga.domain.errors import (
    IdentityVerificationRejected,
    InvalidRegistrationInput,
    RegistrationPersistenceError,
    UserRegistrationExists,
)
from saga.domain.users import (
    RegisterUserCommand,
    StoredPasswordRecord,
    UserRegistered,
    UserRegistration,
)
from saga.ports.clock import Clock
from saga.ports.identity import IdentityVerifier
from saga.ports.random import RandomSource
from saga.ports.registries import UserRegistry
from saga.ports.transactions import UserCreateOutcome


class UserRegistrationService:
    """Register a User according to IV-B without ambient dependencies."""

    def __init__(
        self,
        *,
        identity_verifier: IdentityVerifier,
        user_registry: UserRegistry,
        clock: Clock,
        random_source: RandomSource,
        trust_anchor_der: bytes,
    ) -> None:
        if (
            not isinstance(identity_verifier, IdentityVerifier)
            or not isinstance(user_registry, UserRegistry)
            or not isinstance(clock, Clock)
            or not isinstance(random_source, RandomSource)
            or type(trust_anchor_der) is not bytes
            or not trust_anchor_der
        ):
            raise InvalidRegistrationInput()
        self._identity_verifier = identity_verifier
        self._user_registry = user_registry
        self._clock = clock
        self._random_source = random_source
        self._trust_anchor_der = trust_anchor_der

    def register(self, command: RegisterUserCommand) -> UserRegistered:
        """Validate and atomically persist one User registration."""
        if type(command) is not RegisterUserCommand:
            raise InvalidRegistrationInput()
        if not self._identity_verified(command):
            raise IdentityVerificationRejected()
        self._validate_certificate(command)
        password_record = self._hash_password(command)
        registration = UserRegistration(
            user_id=command.user_id,
            password_record=password_record,
            certificate_der=command.certificate_der,
        )
        outcome = self._create(registration)
        if outcome is UserCreateOutcome.USER_ID_CONFLICT:
            raise UserRegistrationExists()
        if outcome is not UserCreateOutcome.CREATED:
            raise RegistrationPersistenceError()
        return UserRegistered(command.user_id)

    def _identity_verified(self, command: RegisterUserCommand) -> bool:
        try:
            result = self._identity_verifier.verify(command.user_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None
        if type(result) is not bool:
            raise RegistrationPersistenceError()
        return result

    def _validate_certificate(self, command: RegisterUserCommand) -> None:
        try:
            public_key = certificates.validated_leaf_public_key_bytes(
                leaf_der=command.certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=certificates.IdentityKind.USER,
                expected_identifier=command.user_id.value,
                now_ms=self._clock.now_ms(),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise InvalidRegistrationInput() from None
        if type(public_key) is not bytes or len(public_key) != 32:
            raise InvalidRegistrationInput()

    def _hash_password(self, command: RegisterUserCommand) -> StoredPasswordRecord:
        try:
            record = hash_password(
                command.password,
                random_bytes=self._random_source.bytes,
            )
            return StoredPasswordRecord(
                version=record.version,
                n=record.n,
                r=record.r,
                p=record.p,
                dklen=record.dklen,
                salt=record.salt,
                verifier=record.verifier,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise InvalidRegistrationInput() from None

    def _create(self, registration: UserRegistration) -> UserCreateOutcome:
        try:
            outcome = self._user_registry.create_if_absent(registration)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None
        if type(outcome) is not UserCreateOutcome:
            raise RegistrationPersistenceError()
        return outcome


__all__ = ("UserRegistrationService",)
