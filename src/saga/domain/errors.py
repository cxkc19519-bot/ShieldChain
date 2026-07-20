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


class ContactError(Exception):
    """Base class for the closed public contact-state failure surface."""

    _message = "contact operation failed"

    def __init__(self) -> None:
        super().__init__(self._message)


class InvalidContactInput(ContactError):
    _message = "invalid contact input"


class InvalidContactPolicy(ContactError):
    _message = "invalid contact policy"


class ContactPolicyNoMatch(ContactError):
    _message = "contact policy has no match"


class ContactPolicyDenied(ContactError):
    _message = "contact policy denied"


class PairBudgetExhausted(ContactError):
    _message = "contact pair budget exhausted"


class PublicOtkPoolExhausted(ContactError):
    _message = "public OTK pool exhausted"


class AgentInactive(ContactError):
    _message = "receiving Agent is inactive"


class ContactBundleVerificationFailed(ContactError):
    _message = "contact bundle verification failed"


class ConcurrentContactConflict(ContactError):
    _message = "concurrent contact conflict"


class ContactPersistenceError(ContactError):
    _message = "contact persistence failed"


__all__ = (
    "AgentEndpointExists",
    "AgentIdentifierExists",
    "AgentOwnerAuthenticationFailed",
    "AgentRegistrationVerificationFailed",
    "AgentInactive",
    "ConcurrentContactConflict",
    "ContactBundleVerificationFailed",
    "ContactError",
    "ContactPersistenceError",
    "ContactPolicyDenied",
    "ContactPolicyNoMatch",
    "IdentityVerificationRejected",
    "InvalidContactInput",
    "InvalidContactPolicy",
    "InvalidRegistrationInput",
    "PairBudgetExhausted",
    "PublicOtkPoolExhausted",
    "RegistrationError",
    "RegistrationPersistenceError",
    "UserRegistrationExists",
)
