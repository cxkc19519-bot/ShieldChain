from typing import Protocol, runtime_checkable

from saga.domain.agents import AgentId, AgentRegistration
from saga.domain.users import UserId, UserRegistration

from .transactions import AgentCreateOutcome, UserCreateOutcome


@runtime_checkable
class UserRegistry(Protocol):
    def get(self, user_id: UserId) -> UserRegistration | None: ...

    def create_if_absent(self, registration: UserRegistration) -> UserCreateOutcome: ...


@runtime_checkable
class AgentRegistry(Protocol):
    def get(self, agent_id: AgentId) -> AgentRegistration | None: ...

    def create_if_unique(self, registration: AgentRegistration) -> AgentCreateOutcome: ...


__all__ = ("AgentRegistry", "UserRegistry")
