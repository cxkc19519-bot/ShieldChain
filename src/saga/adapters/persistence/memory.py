"""Thread-safe in-memory User registration persistence."""

from __future__ import annotations

from threading import RLock

from saga.domain.agents import AgentId, AgentRegistration
from saga.domain.errors import RegistrationPersistenceError
from saga.domain.users import UserId, UserRegistration
from saga.ports.transactions import AgentCreateOutcome, UserCreateOutcome


class InMemoryUserRegistry:
    """An atomic, thread-safe UserRegistry adapter."""

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


class InMemoryAgentRegistry:
    """An atomic, thread-safe AgentRegistry with global endpoint uniqueness."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[AgentId, AgentRegistration] = {}
        self._agent_ids_by_endpoint: dict[tuple[str, str, int], AgentId] = {}

    def get(self, agent_id: AgentId) -> AgentRegistration | None:
        if type(agent_id) is not AgentId:
            raise RegistrationPersistenceError()
        try:
            with self._lock:
                return self._registrations.get(agent_id)
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None

    def create_if_unique(self, registration: AgentRegistration) -> AgentCreateOutcome:
        if type(registration) is not AgentRegistration:
            raise RegistrationPersistenceError()
        endpoint = registration.endpoint
        endpoint_key: tuple[str, str, int] = (endpoint.device, endpoint.ip, endpoint.port)
        try:
            with self._lock:
                if registration.agent_id in self._registrations:
                    return AgentCreateOutcome.AGENT_ID_CONFLICT
                if endpoint_key in self._agent_ids_by_endpoint:
                    return AgentCreateOutcome.ENDPOINT_CONFLICT
                try:
                    self._registrations[registration.agent_id] = registration
                    self._agent_ids_by_endpoint[endpoint_key] = registration.agent_id
                except BaseException:
                    self._registrations.pop(registration.agent_id, None)
                    self._agent_ids_by_endpoint.pop(endpoint_key, None)
                    raise
                return AgentCreateOutcome.CREATED
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None


__all__ = ("InMemoryAgentRegistry", "InMemoryUserRegistry")
