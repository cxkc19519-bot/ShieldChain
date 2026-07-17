from dataclasses import dataclass

from .encoding import EndpointValue
from .errors import InvalidRegistrationInput
from .users import UserId, _require_certificate, _require_password, _valid_identifier


def _require_plain_bytes(value: object, length: int) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise InvalidRegistrationInput()
    return value


def _require_policy(value: object) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= 65_536:
        raise InvalidRegistrationInput()
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise InvalidRegistrationInput() from None
    return value


@dataclass(frozen=True, slots=True)
class AgentId:
    owner: UserId
    name: str

    def __post_init__(self) -> None:
        if type(self.owner) is not UserId or not _valid_identifier(self.name, max_bytes=128):
            raise InvalidRegistrationInput()

    @property
    def value(self) -> str:
        return f"{self.owner.value}:{self.name}"


@dataclass(frozen=True, slots=True)
class RegisteredPublicOtk:
    public_key: bytes
    user_signature: bytes

    def __post_init__(self) -> None:
        _require_plain_bytes(self.public_key, 32)
        _require_plain_bytes(self.user_signature, 64)


def _validate_agent_material(
    *,
    agent_id: object,
    owner_id: object,
    endpoint: object,
    certificate_der: object,
    access_control_public_key: object,
    contact_policy_document: object,
    public_otks: object,
    user_metadata_signature: object,
) -> None:
    if (
        type(agent_id) is not AgentId
        or type(owner_id) is not UserId
        or agent_id.owner != owner_id
        or type(endpoint) is not EndpointValue
    ):
        raise InvalidRegistrationInput()
    _require_certificate(certificate_der)
    _require_plain_bytes(access_control_public_key, 32)
    _require_policy(contact_policy_document)
    _require_plain_bytes(user_metadata_signature, 64)
    if type(public_otks) is not tuple or not 1 <= len(public_otks) <= 1_024:
        raise InvalidRegistrationInput()
    if any(type(entry) is not RegisteredPublicOtk for entry in public_otks):
        raise InvalidRegistrationInput()
    if len({entry.public_key for entry in public_otks}) != len(public_otks):
        raise InvalidRegistrationInput()


@dataclass(frozen=True, slots=True, repr=False)
class AgentRegistration:
    agent_id: AgentId
    owner_id: UserId
    endpoint: EndpointValue
    certificate_der: bytes
    access_control_public_key: bytes
    contact_policy_document: bytes
    public_otks: tuple[RegisteredPublicOtk, ...]
    user_metadata_signature: bytes

    def __post_init__(self) -> None:
        _validate_agent_material(
            agent_id=self.agent_id,
            owner_id=self.owner_id,
            endpoint=self.endpoint,
            certificate_der=self.certificate_der,
            access_control_public_key=self.access_control_public_key,
            contact_policy_document=self.contact_policy_document,
            public_otks=self.public_otks,
            user_metadata_signature=self.user_metadata_signature,
        )

    def __repr__(self) -> str:
        return f"AgentRegistration(agent_id={self.agent_id!r}, owner_id={self.owner_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class RegisterAgentCommand:
    owner_id: UserId
    password: str
    agent_id: AgentId
    endpoint: EndpointValue
    certificate_der: bytes
    access_control_public_key: bytes
    contact_policy_document: bytes
    public_otks: tuple[RegisteredPublicOtk, ...]
    user_metadata_signature: bytes

    def __post_init__(self) -> None:
        _require_password(self.password)
        _validate_agent_material(
            agent_id=self.agent_id,
            owner_id=self.owner_id,
            endpoint=self.endpoint,
            certificate_der=self.certificate_der,
            access_control_public_key=self.access_control_public_key,
            contact_policy_document=self.contact_policy_document,
            public_otks=self.public_otks,
            user_metadata_signature=self.user_metadata_signature,
        )

    def __repr__(self) -> str:
        return f"RegisterAgentCommand(agent_id={self.agent_id!r}, owner_id={self.owner_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class AgentRegistered:
    agent_id: AgentId
    provider_attestation_signature: bytes

    def __post_init__(self) -> None:
        if type(self.agent_id) is not AgentId:
            raise InvalidRegistrationInput()
        _require_plain_bytes(self.provider_attestation_signature, 64)


__all__ = (
    "AgentId",
    "AgentRegistered",
    "AgentRegistration",
    "RegisteredPublicOtk",
    "RegisterAgentCommand",
)
