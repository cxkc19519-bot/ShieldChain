"""Thread-safe in-memory User registration persistence."""

from __future__ import annotations

from threading import RLock

from saga.domain.errors import RegistrationPersistenceError
from saga.domain.users import UserId, UserRegistration
from saga.ports.transactions import UserCreateOutcome


class InMemoryUserRegistry:
    """An atomic UserRegistry adapter; Agent persistence is deliberately deferred."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[UserId, UserRegistration] = {}

    def get(self, user_id: UserId) -> UserRegistration | None:
        if type(user_id) is not UserId:
            raise RegistrationPersistenceError()
        try:
            with self._lock:
                return self._registrations.get(user_id)
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None

    def create_if_absent(self, registration: UserRegistration) -> UserCreateOutcome:
        if type(registration) is not UserRegistration:
            raise RegistrationPersistenceError()
        try:
            with self._lock:
                if registration.user_id in self._registrations:
                    return UserCreateOutcome.USER_ID_CONFLICT
                self._registrations[registration.user_id] = registration
                return UserCreateOutcome.CREATED
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None


__all__ = ("InMemoryUserRegistry",)
