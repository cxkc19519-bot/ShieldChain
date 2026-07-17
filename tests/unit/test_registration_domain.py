import dataclasses
import subprocess
import sys

import pytest

from saga.crypto.passwords import PasswordRecord
from saga.domain import (
    AgentEndpointExists,
    AgentId,
    AgentIdentifierExists,
    AgentOwnerAuthenticationFailed,
    AgentRegistered,
    AgentRegistration,
    AgentRegistrationVerificationFailed,
    EndpointValue,
    IdentityVerificationRejected,
    InvalidRegistrationInput,
    RegisterAgentCommand,
    RegisteredPublicOtk,
    RegisterUserCommand,
    RegistrationEvent,
    RegistrationPersistenceError,
    UserId,
    UserRegistered,
    UserRegistration,
    UserRegistrationExists,
)
from saga.domain.users import StoredPasswordRecord


class StrSubclass(str):
    pass


class BytesSubclass(bytes):
    pass


class IntSubclass(int):
    pass


def password_record() -> StoredPasswordRecord:
    return StoredPasswordRecord(1, 2**15, 8, 1, 32, b"s" * 16, b"v" * 32)


def otk(marker: int = 0) -> RegisteredPublicOtk:
    return RegisteredPublicOtk(bytes([marker % 256]) * 32, b"g" * 64)


def agent_kwargs() -> dict[str, object]:
    owner = UserId("alice")
    return {
        "agent_id": AgentId(owner, "phone"),
        "owner_id": owner,
        "endpoint": EndpointValue("pixel", "192.0.2.1", 443),
        "certificate_der": b"certificate",
        "access_control_public_key": b"a" * 32,
        "contact_policy_document": "允许".encode(),
        "public_otks": (otk(),),
        "user_metadata_signature": b"m" * 64,
    }


@pytest.mark.parametrize(
    "value",
    ["", " alice", "alice ", "ali:ce", "ali\x00ce", "ali\nce", StrSubclass("alice")],
)
def test_user_id_rejects_noncanonical_values(value: object) -> None:
    with pytest.raises(InvalidRegistrationInput, match="^invalid registration input$"):
        UserId(value)  # type: ignore[arg-type]


def test_user_id_uses_utf8_byte_bound_and_is_immutable() -> None:
    assert UserId("é" * 127).value == "é" * 127
    assert UserId("a" * 254).value == "a" * 254
    with pytest.raises(InvalidRegistrationInput):
        UserId("é" * 128)
    with pytest.raises(InvalidRegistrationInput):
        UserId("\ud800")
    with pytest.raises(dataclasses.FrozenInstanceError):
        UserId("alice").value = "bob"  # type: ignore[misc]


@pytest.mark.parametrize(
    "name",
    ["", " phone", "phone ", "ph:one", "ph\x00one", StrSubclass("phone")],
)
def test_agent_id_rejects_noncanonical_names(name: object) -> None:
    with pytest.raises(InvalidRegistrationInput):
        AgentId(UserId("alice"), name)  # type: ignore[arg-type]


def test_agent_id_is_canonical_bounded_and_strictly_typed() -> None:
    owner = UserId("用户")
    value = AgentId(owner, "代" * 42)
    assert value.value == f"{owner.value}:{'代' * 42}"
    assert value == AgentId(owner, "代" * 42)
    with pytest.raises(InvalidRegistrationInput):
        AgentId(owner, "代" * 43)
    with pytest.raises(InvalidRegistrationInput):
        AgentId("用户", "phone")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"version": True},
        {"n": IntSubclass(2**15)},
        {"r": 7},
        {"p": 2},
        {"dklen": 31},
        {"salt": BytesSubclass(b"s" * 16)},
        {"salt": b"s" * 15},
        {"verifier": b"v" * 31},
    ],
)
def test_stored_password_record_is_fixed_and_strict(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "version": 1,
        "n": 2**15,
        "r": 8,
        "p": 1,
        "dklen": 32,
        "salt": b"s" * 16,
        "verifier": b"v" * 32,
    }
    values.update(changes)
    with pytest.raises(InvalidRegistrationInput):
        StoredPasswordRecord(**values)  # type: ignore[arg-type]


def test_stored_password_record_is_redacted_and_structurally_mappable() -> None:
    stored = password_record()
    assert repr(stored) == "StoredPasswordRecord(version=1, redacted=True)"
    crypto = PasswordRecord(
        stored.version,
        stored.n,
        stored.r,
        stored.p,
        stored.dklen,
        stored.salt,
        stored.verifier,
    )
    restored = StoredPasswordRecord(
        crypto.version, crypto.n, crypto.r, crypto.p, crypto.dklen, crypto.salt, crypto.verifier
    )
    assert restored == stored


@pytest.mark.parametrize("key", [b"k" * 31, b"k" * 33, BytesSubclass(b"k" * 32)])
def test_public_otk_rejects_non_exact_plain_key(key: bytes) -> None:
    with pytest.raises(InvalidRegistrationInput):
        RegisteredPublicOtk(key, b"s" * 64)


@pytest.mark.parametrize("signature", [b"s" * 63, b"s" * 65, BytesSubclass(b"s" * 64)])
def test_public_otk_rejects_non_exact_plain_signature(signature: bytes) -> None:
    with pytest.raises(InvalidRegistrationInput):
        RegisteredPublicOtk(b"k" * 32, signature)


def test_user_registration_and_command_validate_bounds_and_redact() -> None:
    uid = UserId("alice")
    record = UserRegistration(uid, password_record(), b"c")
    command = RegisterUserCommand(uid, "密" * 341 + "a", b"c" * 16384)
    assert "certificate" not in repr(record).lower()
    assert "password" not in repr(command).lower()
    assert "密" not in repr(command)
    for invalid in ("", "密" * 342, StrSubclass("password")):
        with pytest.raises(InvalidRegistrationInput):
            RegisterUserCommand(uid, invalid, b"c")
    for invalid_cert in (b"", b"c" * 16385, BytesSubclass(b"c")):
        with pytest.raises(InvalidRegistrationInput):
            RegisterUserCommand(uid, "password", invalid_cert)
    with pytest.raises(InvalidRegistrationInput):
        UserRegistration(uid, password_record(), BytesSubclass(b"c"))


def test_agent_registration_validates_owner_types_and_redacts() -> None:
    kwargs = agent_kwargs()
    registration = AgentRegistration(**kwargs)  # type: ignore[arg-type]
    assert "certificate" not in repr(registration).lower()
    assert "signature" not in repr(registration).lower()
    wrong_owner = dict(kwargs, owner_id=UserId("bob"))
    with pytest.raises(InvalidRegistrationInput):
        AgentRegistration(**wrong_owner)  # type: ignore[arg-type]
    with pytest.raises(InvalidRegistrationInput):
        AgentRegistration(**dict(kwargs, endpoint=object()))  # type: ignore[arg-type]


def test_agent_material_bounds_policy_opacity_and_otk_uniqueness() -> None:
    kwargs = agent_kwargs()
    assert AgentRegistration(**kwargs).contact_policy_document == "允许".encode()  # type: ignore[arg-type]
    for policy in (b"", b"x" * 65537, b"\xff", BytesSubclass(b"x")):
        with pytest.raises(InvalidRegistrationInput):
            AgentRegistration(**dict(kwargs, contact_policy_document=policy))  # type: ignore[arg-type]
    for key in (b"a" * 31, BytesSubclass(b"a" * 32)):
        with pytest.raises(InvalidRegistrationInput):
            AgentRegistration(**dict(kwargs, access_control_public_key=key))  # type: ignore[arg-type]
    for signature in (b"m" * 63, BytesSubclass(b"m" * 64)):
        with pytest.raises(InvalidRegistrationInput):
            AgentRegistration(**dict(kwargs, user_metadata_signature=signature))  # type: ignore[arg-type]
    for entries in ((), (otk(), otk())):
        with pytest.raises(InvalidRegistrationInput):
            AgentRegistration(**dict(kwargs, public_otks=entries))  # type: ignore[arg-type]
    valid_max = tuple(otk(i) for i in range(256)) * 4
    # Repeated key material is rejected even when the tuple length itself is valid.
    with pytest.raises(InvalidRegistrationInput):
        AgentRegistration(**dict(kwargs, public_otks=valid_max))  # type: ignore[arg-type]
    unique = tuple(RegisteredPublicOtk(i.to_bytes(32, "big"), b"s" * 64) for i in range(1024))
    assert len(AgentRegistration(**dict(kwargs, public_otks=unique)).public_otks) == 1024  # type: ignore[arg-type]
    with pytest.raises(InvalidRegistrationInput):
        AgentRegistration(**dict(kwargs, public_otks=unique + (otk(),)))  # type: ignore[arg-type]
    with pytest.raises(InvalidRegistrationInput):
        AgentRegistration(**dict(kwargs, public_otks=list(unique)))  # type: ignore[arg-type]


def test_agent_command_validates_password_certificate_and_is_redacted() -> None:
    kwargs = agent_kwargs()
    command = RegisterAgentCommand(password="hidden-password", **kwargs)  # type: ignore[arg-type]
    text = repr(command)
    assert "hidden-password" not in text
    assert "certificate" not in text.lower()
    assert "signature" not in text.lower()
    for password in ("", "x" * 1025, StrSubclass("password")):
        with pytest.raises(InvalidRegistrationInput):
            RegisterAgentCommand(password=password, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(InvalidRegistrationInput):
        RegisterAgentCommand(password="password", **dict(kwargs, certificate_der=b""))  # type: ignore[arg-type]


def test_results_are_public_only_and_validate_provider_signature() -> None:
    uid = UserId("alice")
    aid = AgentId(uid, "phone")
    assert [field.name for field in dataclasses.fields(UserRegistered)] == ["user_id"]
    assert [field.name for field in dataclasses.fields(AgentRegistered)] == [
        "agent_id",
        "provider_attestation_signature",
    ]
    assert UserRegistered(uid).user_id == uid
    assert AgentRegistered(aid, b"s" * 64).agent_id == aid
    with pytest.raises(InvalidRegistrationInput):
        AgentRegistered(aid, BytesSubclass(b"s" * 64))


@pytest.mark.parametrize(
    ("error_type", "message"),
    [
        (InvalidRegistrationInput, "invalid registration input"),
        (IdentityVerificationRejected, "identity verification rejected"),
        (UserRegistrationExists, "User registration already exists"),
        (AgentOwnerAuthenticationFailed, "Agent owner authentication failed"),
        (AgentRegistrationVerificationFailed, "Agent registration verification failed"),
        (AgentIdentifierExists, "Agent identifier already exists"),
        (AgentEndpointExists, "Agent endpoint already exists"),
        (RegistrationPersistenceError, "registration persistence failed"),
    ],
)
def test_registration_errors_have_fixed_messages(error_type: type[Exception], message: str) -> None:
    error = error_type()
    assert str(error) == message
    assert error.args == (message,)


def test_registration_event_schema_is_closed_public_and_immutable() -> None:
    uid = UserId("alice")
    aid = AgentId(uid, "phone")
    correlation_id = "12345678-1234-5678-9234-abcdefabcdef"
    event = RegistrationEvent("agent_registration", uid, aid, "created", 7, correlation_id)
    assert [field.name for field in dataclasses.fields(event)] == [
        "event_name",
        "user_id",
        "agent_id",
        "result",
        "duration_ms",
        "correlation_id",
    ]
    assert "password" not in repr(event).lower()
    assert repr(event) == (
        "RegistrationEvent(event_name='agent_registration', user_id=UserId(value='alice'), "
        "agent_id=AgentId(owner=UserId(value='alice'), name='phone'), result='created', "
        "duration_ms=7, correlation_id='12345678-1234-5678-9234-abcdefabcdef')"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.result = "failed"  # type: ignore[misc]
    for bad in (
        ("", uid, aid, "created", 7, correlation_id),
        ("private-key-material", uid, aid, "created", 7, correlation_id),
        ("agent_registration", uid, aid, "", 7, correlation_id),
        ("agent_registration", uid, aid, "password=secret", 7, correlation_id),
        ("agent_registration", uid, aid, "created", True, correlation_id),
        ("agent_registration", uid, aid, "created", -1, correlation_id),
        ("agent_registration", uid, aid, "created", 7, ""),
        ("agent_registration", uid, aid, "created", 7, "private-key-material"),
        ("agent_registration", None, aid, "created", 7, correlation_id),
        ("user_registration", None, None, "created", 7, correlation_id),
        ("user_registration", uid, aid, "created", 7, correlation_id),
        ("agent_registration", uid, None, "created", 7, correlation_id),
        (
            "agent_registration",
            uid,
            aid,
            "created",
            7,
            "12345678-1234-5678-9234-abcdefabcdef".upper(),
        ),
        ("agent_registration", uid, aid, "created", 7, "{12345678-1234-5678-9234-abcdefabcdef}"),
        (
            "agent_registration",
            uid,
            aid,
            "created",
            7,
            StrSubclass("12345678-1234-5678-9234-abcdefabcdef"),
        ),
    ):
        with pytest.raises(InvalidRegistrationInput):
            RegistrationEvent(*bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("event_name", ["user_registration", "agent_registration"])
@pytest.mark.parametrize("result", ["created", "rejected", "conflict", "failed"])
def test_registration_event_accepts_exact_public_closed_sets(event_name: str, result: str) -> None:
    uid = UserId("alice")
    agent_id = AgentId(uid, "phone") if event_name == "agent_registration" else None
    event = RegistrationEvent(
        event_name,
        uid,
        agent_id,
        result,
        0,
        "12345678-1234-5678-9234-abcdefabcdef",
    )
    assert event.event_name == event_name
    assert event.result == result


def test_domain_import_boundary_in_fresh_process() -> None:
    script = (
        "import sys; import saga.domain; "
        "assert 'saga.crypto' not in sys.modules; "
        "assert not any(name == 'cryptography' or name.startswith('cryptography.') "
        "for name in sys.modules)"
    )
    subprocess.run([sys.executable, "-I", "-c", script], check=True)  # noqa: S603
