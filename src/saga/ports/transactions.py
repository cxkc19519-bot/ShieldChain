from enum import StrEnum as _StrEnum


class UserCreateOutcome(_StrEnum):
    CREATED = "created"
    USER_ID_CONFLICT = "user_id_conflict"


class AgentCreateOutcome(_StrEnum):
    CREATED = "created"
    AGENT_ID_CONFLICT = "agent_id_conflict"
    ENDPOINT_CONFLICT = "endpoint_conflict"


__all__ = ("AgentCreateOutcome", "UserCreateOutcome")
