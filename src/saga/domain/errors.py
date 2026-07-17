class RegistrationError(Exception):
    """Base class for the closed public registration failure surface."""

    _message = "registration failed"

    def __init__(self) -> None:
        super().__init__(self._message)


class InvalidRegistrationInput(RegistrationError):
    _message = "invalid registration input"


class IdentityVerificationRejected(RegistrationError):
    _message = "identity verification rejected"


class UserRegistrationExists(RegistrationError):
    _message = "User registration already exists"


class AgentOwnerAuthenticationFailed(RegistrationError):
    _message = "Agent owner authentication failed"


class AgentRegistrationVerificationFailed(RegistrationError):
    _message = "Agent registration verification failed"


class AgentIdentifierExists(RegistrationError):
    _message = "Agent identifier already exists"


class AgentEndpointExists(RegistrationError):
    _message = "Agent endpoint already exists"


class RegistrationPersistenceError(RegistrationError):
    _message = "registration persistence failed"


__all__ = (
    "AgentEndpointExists",
    "AgentIdentifierExists",
    "AgentOwnerAuthenticationFailed",
    "AgentRegistrationVerificationFailed",
    "IdentityVerificationRejected",
    "InvalidRegistrationInput",
    "RegistrationError",
    "RegistrationPersistenceError",
    "UserRegistrationExists",
)
