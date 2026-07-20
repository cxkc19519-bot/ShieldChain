"""Immutable Phase 3 contact-state contracts; no persistence or state transitions."""

from __future__ import annotations

from dataclasses import dataclass

from .agents import AgentId, AgentRegistration, RegisteredPublicOtk
from .encoding import EndpointValue
from .errors import InvalidContactInput
from .otk import (
    AvailablePublicOtk,
    PairCounter,
    PublicOtkId,
    _non_negative,
    validate_new_public_otks,
)
from .policies import ContactPolicy
from .users import UserId, _require_certificate, _require_password


def _bytes(value: object, length: int | None = None) -> bytes:
    if type(value) is not bytes or (length is not None and len(value) != length):
        raise InvalidContactInput()
    return value


def _policy_bytes(value: object, *, strict: bool) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= 65_536:
        raise InvalidContactInput()
    try:
        value.decode("utf-8", errors="strict")
        if strict:
            ContactPolicy.parse(value)
    except UnicodeDecodeError:
        raise InvalidContactInput() from None
    return value


@dataclass(frozen=True, slots=True)
class ContactSnapshot:
    receiving_registration: AgentRegistration | None
    initiating_registration: AgentRegistration | None
    receiving_active: bool
    agent_revision: int
    contact_policy_document: bytes
    policy_version: int
    pair_counter: PairCounter | None
    available_public_otks: tuple[AvailablePublicOtk, ...]
    otk_pool_revision: int

    def __post_init__(self) -> None:
        if type(self.receiving_registration) not in (AgentRegistration, type(None)):
            raise InvalidContactInput()
        if type(self.initiating_registration) not in (AgentRegistration, type(None)):
            raise InvalidContactInput()
        if type(self.receiving_active) is not bool:
            raise InvalidContactInput()
        _non_negative(self.agent_revision)
        _policy_bytes(self.contact_policy_document, strict=False)
        _non_negative(self.policy_version)
        if self.pair_counter is not None and type(self.pair_counter) is not PairCounter:
            raise InvalidContactInput()
        if (
            self.pair_counter is not None
            and self.receiving_registration is not None
            and self.initiating_registration is not None
            and (
                self.pair_counter.receiving_agent_id != self.receiving_registration.agent_id
                or self.pair_counter.initiating_agent_id != self.initiating_registration.agent_id
            )
        ):
            raise InvalidContactInput()
        if type(self.available_public_otks) is not tuple or any(
            type(otk) is not AvailablePublicOtk for otk in self.available_public_otks
        ):
            raise InvalidContactInput()
        ordinals = tuple(otk.otk_id.ordinal for otk in self.available_public_otks)
        if ordinals != tuple(sorted(ordinals)) or len(ordinals) != len(set(ordinals)):
            raise InvalidContactInput()
        if self.receiving_registration is not None and any(
            otk.otk_id.receiving_agent_id != self.receiving_registration.agent_id
            for otk in self.available_public_otks
        ):
            raise InvalidContactInput()
        _non_negative(self.otk_pool_revision)


@dataclass(frozen=True, slots=True)
class ContactCommit:
    receiving_agent_id: AgentId
    initiating_agent_id: AgentId
    selected_public_otk_id: PublicOtkId
    remaining: int
    expected_agent_revision: int
    expected_active: bool
    expected_policy_version: int
    expected_counter: PairCounter | None
    expected_otk_pool_revision: int

    def __post_init__(self) -> None:
        if (
            type(self.receiving_agent_id) is not AgentId
            or type(self.initiating_agent_id) is not AgentId
            or type(self.selected_public_otk_id) is not PublicOtkId
            or self.selected_public_otk_id.receiving_agent_id != self.receiving_agent_id
            or type(self.expected_active) is not bool
        ):
            raise InvalidContactInput()
        _non_negative(self.remaining)
        _non_negative(self.expected_agent_revision)
        _non_negative(self.expected_policy_version)
        _non_negative(self.expected_otk_pool_revision)
        if self.expected_counter is not None:
            if (
                type(self.expected_counter) is not PairCounter
                or self.expected_counter.receiving_agent_id != self.receiving_agent_id
                or self.expected_counter.initiating_agent_id != self.initiating_agent_id
            ):
                raise InvalidContactInput()


@dataclass(frozen=True, slots=True, repr=False)
class ContactBundle:
    receiving_user_certificate_der: bytes
    receiving_agent_id: AgentId
    receiving_endpoint: EndpointValue | None
    receiving_agent_certificate_der: bytes
    receiving_access_control_public_key: bytes
    public_otk: AvailablePublicOtk

    def __post_init__(self) -> None:
        try:
            _require_certificate(self.receiving_user_certificate_der)
            _require_certificate(self.receiving_agent_certificate_der)
        except Exception:
            raise InvalidContactInput() from None
        if (
            type(self.receiving_agent_id) is not AgentId
            or type(self.receiving_endpoint) not in (EndpointValue, type(None))
            or type(self.public_otk) is not AvailablePublicOtk
            or self.public_otk.otk_id.receiving_agent_id != self.receiving_agent_id
        ):
            raise InvalidContactInput()
        _bytes(self.receiving_access_control_public_key, 32)

    def __repr__(self) -> str:
        return f"ContactBundle(receiving_agent_id={self.receiving_agent_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class ResolveContactCommand:
    receiving_agent_id: AgentId
    initiating_agent_id: AgentId

    def __post_init__(self) -> None:
        if (
            type(self.receiving_agent_id) is not AgentId
            or type(self.initiating_agent_id) is not AgentId
        ):
            raise InvalidContactInput()

    def __repr__(self) -> str:
        return (
            f"ResolveContactCommand(receiving_agent_id={self.receiving_agent_id!r}, "
            f"initiating_agent_id={self.initiating_agent_id!r}, redacted=True)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class UpdateContactPolicyCommand:
    owner_id: UserId
    password: str
    agent_id: AgentId
    contact_policy_document: bytes

    def __post_init__(self) -> None:
        if (
            type(self.owner_id) is not UserId
            or type(self.agent_id) is not AgentId
            or self.agent_id.owner != self.owner_id
        ):
            raise InvalidContactInput()
        try:
            _require_password(self.password)
        except Exception:
            raise InvalidContactInput() from None
        _policy_bytes(self.contact_policy_document, strict=True)

    def __repr__(self) -> str:
        return f"UpdateContactPolicyCommand(agent_id={self.agent_id!r}, owner_id={self.owner_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class AppendPublicOtksCommand:
    owner_id: UserId
    password: str
    agent_id: AgentId
    public_otks: tuple[RegisteredPublicOtk, ...]

    def __post_init__(self) -> None:
        if (
            type(self.owner_id) is not UserId
            or type(self.agent_id) is not AgentId
            or self.agent_id.owner != self.owner_id
        ):
            raise InvalidContactInput()
        try:
            _require_password(self.password)
        except Exception:
            raise InvalidContactInput() from None
        validate_new_public_otks(self.public_otks)

    def __repr__(self) -> str:
        return f"AppendPublicOtksCommand(agent_id={self.agent_id!r}, owner_id={self.owner_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class DeactivateAgentCommand:
    owner_id: UserId
    password: str
    agent_id: AgentId

    def __post_init__(self) -> None:
        if (
            type(self.owner_id) is not UserId
            or type(self.agent_id) is not AgentId
            or self.agent_id.owner != self.owner_id
        ):
            raise InvalidContactInput()
        try:
            _require_password(self.password)
        except Exception:
            raise InvalidContactInput() from None

    def __repr__(self) -> str:
        return f"DeactivateAgentCommand(agent_id={self.agent_id!r}, owner_id={self.owner_id!r}, redacted=True)"


__all__ = (
    "AppendPublicOtksCommand",
    "ContactBundle",
    "ContactCommit",
    "ContactSnapshot",
    "DeactivateAgentCommand",
    "ResolveContactCommand",
    "UpdateContactPolicyCommand",
)
