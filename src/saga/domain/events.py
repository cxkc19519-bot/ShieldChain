from dataclasses import dataclass
from uuid import UUID

from .agents import AgentId
from .errors import InvalidRegistrationInput
from .users import UserId

_EVENT_NAMES = frozenset({"user_registration", "agent_registration"})
_RESULTS = frozenset({"created", "rejected", "conflict", "failed"})


def _valid_correlation_id(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class RegistrationEvent:
    event_name: str
    user_id: UserId
    agent_id: AgentId | None
    result: str
    duration_ms: int
    correlation_id: str

    def __post_init__(self) -> None:
        if not (
            type(self.event_name) is str
            and self.event_name in _EVENT_NAMES
            and type(self.user_id) is UserId
            and (self.agent_id is None or type(self.agent_id) is AgentId)
            and type(self.result) is str
            and self.result in _RESULTS
            and type(self.duration_ms) is int
            and self.duration_ms >= 0
            and _valid_correlation_id(self.correlation_id)
        ):
            raise InvalidRegistrationInput()
        expected_agent = self.event_name == "agent_registration"
        if expected_agent != (self.agent_id is not None):
            raise InvalidRegistrationInput()
        if self.agent_id is not None and self.agent_id.owner != self.user_id:
            raise InvalidRegistrationInput()


__all__ = ("RegistrationEvent",)
