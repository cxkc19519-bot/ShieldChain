import inspect
import subprocess
import sys
from enum import StrEnum
from typing import get_type_hints

import pytest

from saga.domain import (
    AgentId,
    AgentRegistration,
    RegistrationPersistenceError,
    UserId,
    UserRegistration,
)
from saga.ports import (
    AgentCreateOutcome,
    AgentRegistry,
    Clock,
    IdentityVerifier,
    ProviderSigner,
    RandomSource,
    UserCreateOutcome,
    UserRegistry,
)
from tests.helpers.registration import (
    DeterministicRandomSource,
    FakeProviderSigner,
    FixedClock,
    TrustedIdentityVerifier,
)


class BytesSubclass(bytes):
    pass


class IntSubclass(int):
    pass


class MemoryUserPort:
    def get(self, user_id: UserId) -> UserRegistration | None:
        del user_id
        return None

    def create_if_absent(self, registration: UserRegistration) -> UserCreateOutcome:
        del registration
        return UserCreateOutcome.CREATED


class MemoryAgentPort:
    def get(self, agent_id: AgentId) -> AgentRegistration | None:
        del agent_id
        return None

    def create_if_unique(self, registration: AgentRegistration) -> AgentCreateOutcome:
        del registration
        return AgentCreateOutcome.CREATED


def test_deterministic_substitutes_and_registry_stubs_conform_at_runtime() -> None:
    user_id = UserId("alice")
    assert isinstance(TrustedIdentityVerifier(frozenset({user_id})), IdentityVerifier)
    assert isinstance(FixedClock(1_767_225_600_000), Clock)
    assert isinstance(DeterministicRandomSource((b"s" * 16,)), RandomSource)
    assert isinstance(FakeProviderSigner(b"p" * 32, b"g" * 64), ProviderSigner)
    assert isinstance(MemoryUserPort(), UserRegistry)
    assert isinstance(MemoryAgentPort(), AgentRegistry)


@pytest.mark.parametrize(
    ("protocol", "methods"),
    [
        (IdentityVerifier, {"verify": ["self", "user_id"]}),
        (Clock, {"now_ms": ["self"]}),
        (RandomSource, {"bytes": ["self", "length"]}),
        (
            ProviderSigner,
            {"public_key_bytes": ["self"], "sign": ["self", "message"]},
        ),
        (
            UserRegistry,
            {"get": ["self", "user_id"], "create_if_absent": ["self", "registration"]},
        ),
        (
            AgentRegistry,
            {"get": ["self", "agent_id"], "create_if_unique": ["self", "registration"]},
        ),
    ],
)
def test_port_method_sets_and_parameter_names_are_exact(
    protocol: type[object], methods: dict[str, list[str]]
) -> None:
    public_names = {
        name
        for name, value in vars(protocol).items()
        if not name.startswith("_") and callable(value)
    }
    assert public_names == set(methods)
    for method_name, parameter_names in methods.items():
        assert list(inspect.signature(getattr(protocol, method_name)).parameters) == parameter_names


def test_port_annotations_are_exact() -> None:
    assert get_type_hints(IdentityVerifier.verify) == {
        "user_id": UserId,
        "return": bool,
    }
    assert get_type_hints(Clock.now_ms) == {"return": int}
    assert get_type_hints(RandomSource.bytes) == {"length": int, "return": bytes}
    assert get_type_hints(ProviderSigner.public_key_bytes) == {"return": bytes}
    assert get_type_hints(ProviderSigner.sign) == {"message": bytes, "return": bytes}
    assert get_type_hints(UserRegistry.get) == {
        "user_id": UserId,
        "return": UserRegistration | None,
    }
    assert get_type_hints(UserRegistry.create_if_absent) == {
        "registration": UserRegistration,
        "return": UserCreateOutcome,
    }
    assert get_type_hints(AgentRegistry.get) == {
        "agent_id": AgentId,
        "return": AgentRegistration | None,
    }
    assert get_type_hints(AgentRegistry.create_if_unique) == {
        "registration": AgentRegistration,
        "return": AgentCreateOutcome,
    }


def test_outcomes_are_closed_exact_string_enums() -> None:
    assert issubclass(UserCreateOutcome, StrEnum)
    assert [(item.name, item.value) for item in UserCreateOutcome] == [
        ("CREATED", "created"),
        ("USER_ID_CONFLICT", "user_id_conflict"),
    ]
    assert issubclass(AgentCreateOutcome, StrEnum)
    assert [(item.name, item.value) for item in AgentCreateOutcome] == [
        ("CREATED", "created"),
        ("AGENT_ID_CONFLICT", "agent_id_conflict"),
        ("ENDPOINT_CONFLICT", "endpoint_conflict"),
    ]
    assert "persistence" not in {item.value for item in (*UserCreateOutcome, *AgentCreateOutcome)}
    assert str(RegistrationPersistenceError()) == "registration persistence failed"


def test_transactions_module_owns_only_the_two_outcomes() -> None:
    import saga.ports.transactions as transactions

    assert transactions.__all__ == ("AgentCreateOutcome", "UserCreateOutcome")
    assert {name for name in vars(transactions) if not name.startswith("_")} == {
        "AgentCreateOutcome",
        "UserCreateOutcome",
    }


def test_fixed_clock_accepts_only_strict_valid_unix_milliseconds() -> None:
    clock = FixedClock(1_767_225_600_000)
    assert clock.now_ms() == 1_767_225_600_000
    for invalid in (True, IntSubclass(1), -1):
        with pytest.raises(ValueError):
            FixedClock(invalid)  # type: ignore[arg-type]


def test_random_source_is_ordered_strict_and_redacted() -> None:
    source = DeterministicRandomSource((b"a" * 16, b"b" * 32))
    assert "a" * 16 not in repr(source)
    assert source.bytes(16) == b"a" * 16
    assert source.bytes(32) == b"b" * 32
    with pytest.raises(ValueError, match="^deterministic random source exhausted$"):
        source.bytes(1)
    for invalid in (True, IntSubclass(16), 0, -1):
        with pytest.raises(ValueError, match="^random length invalid$"):
            DeterministicRandomSource((b"x" * 16,)).bytes(invalid)  # type: ignore[arg-type]
    for outputs in ([b"x"], (BytesSubclass(b"x"),)):
        with pytest.raises(ValueError, match="^deterministic random results invalid$"):
            DeterministicRandomSource(outputs)  # type: ignore[arg-type]
    malformed_length = DeterministicRandomSource((b"x" * 15,))
    with pytest.raises(ValueError, match="^deterministic random result invalid$"):
        malformed_length.bytes(16)
    assert malformed_length.bytes(15) == b"x" * 15


def test_identity_substitute_has_an_explicit_strict_closed_set() -> None:
    alice = UserId("alice")
    bob = UserId("bob")
    verifier = TrustedIdentityVerifier(frozenset({alice}))
    assert verifier.verify(alice)
    assert not verifier.verify(bob)
    with pytest.raises(ValueError, match="^trusted identities invalid$"):
        TrustedIdentityVerifier({alice})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^identity input invalid$"):
        verifier.verify("alice")  # type: ignore[arg-type]


def test_fake_provider_signer_is_strict_observable_and_redacted() -> None:
    signer = FakeProviderSigner(b"p" * 32, b"g" * 64)
    assert signer.public_key_bytes() == b"p" * 32
    assert signer.sign(b"message") == b"g" * 64
    assert signer.signed_messages == (b"message",)
    assert "p" * 32 not in repr(signer)
    assert "g" * 64 not in repr(signer)
    for public_key, signature in (
        (b"p" * 31, b"g" * 64),
        (BytesSubclass(b"p" * 32), b"g" * 64),
        (b"p" * 32, b"g" * 63),
        (b"p" * 32, BytesSubclass(b"g" * 64)),
    ):
        with pytest.raises(ValueError, match="^provider signer material invalid$"):
            FakeProviderSigner(public_key, signature)
    with pytest.raises(ValueError, match="^signing message invalid$"):
        signer.sign(BytesSubclass(b"message"))


def test_ports_import_boundary_in_fresh_process() -> None:
    script = (
        "import sys; import saga.ports; "
        "assert 'saga.crypto' not in sys.modules; "
        "assert not any(name == 'cryptography' or name.startswith('cryptography.') "
        "for name in sys.modules); "
        "assert not any(name.startswith('saga.protocols') for name in sys.modules); "
        "assert not any(name.startswith('saga.adapters') for name in sys.modules)"
    )
    subprocess.run([sys.executable, "-I", "-c", script], check=True)  # noqa: S603
