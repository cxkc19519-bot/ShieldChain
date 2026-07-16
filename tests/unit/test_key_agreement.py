import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from saga.crypto.key_agreement import (
    KeyAgreementError,
    derive_shared_secret,
    generate_x25519_private_key,
    x25519_public_key,
    x25519_public_key_bytes,
    x25519_public_key_from_bytes,
)


def test_rfc7748_alice_bob_shared_secret() -> None:
    alice = X25519PrivateKey.from_private_bytes(
        bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    )
    bob = X25519PrivateKey.from_private_bytes(
        bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    )
    expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert derive_shared_secret(alice, bob.public_key()).hex() == expected
    assert derive_shared_secret(bob, alice.public_key()).hex() == expected


def test_saga_dh_ledger_equality() -> None:
    # SAC_B pairs with PAC_B; SOTK_A pairs with OTK_A.
    sac_b = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    sotk_a = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    pac_b = sac_b.public_key()
    otk_a = sotk_a.public_key()
    assert derive_shared_secret(sac_b, otk_a) == derive_shared_secret(sotk_a, pac_b)


def test_x25519_key_generation_and_raw_public_round_trip() -> None:
    private = generate_x25519_private_key()
    public = x25519_public_key(private)
    raw = x25519_public_key_bytes(public)
    assert type(raw) is bytes and len(raw) == 32
    assert x25519_public_key_bytes(x25519_public_key_from_bytes(raw)) == raw


def test_x25519_wrong_objects_and_lengths_fail() -> None:
    private = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    calls = [
        lambda: x25519_public_key(object()),
        lambda: x25519_public_key_bytes(object()),
        lambda: x25519_public_key_from_bytes(object()),
        lambda: derive_shared_secret(object(), public),
        lambda: derive_shared_secret(private, object()),
    ]
    calls.extend(lambda n=n: x25519_public_key_from_bytes(b"0" * n) for n in (0, 31, 33))
    for call in calls:
        with pytest.raises(KeyAgreementError):
            call()


class FakeXPublic:
    @classmethod
    def from_public_bytes(cls, _: bytes) -> "FakeXPublic":
        raise ValueError

    def public_bytes(self, *_: object) -> bytes:
        raise TypeError


class FakeXPrivate:
    @classmethod
    def generate(cls) -> "FakeXPrivate":
        raise ValueError

    def public_key(self) -> FakeXPublic:
        raise TypeError

    def exchange(self, _: FakeXPublic) -> bytes:
        return b"\x00" * 32


def test_x25519_library_errors_are_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("saga.crypto.key_agreement.X25519PrivateKey", FakeXPrivate)
    monkeypatch.setattr("saga.crypto.key_agreement.X25519PublicKey", FakeXPublic)
    calls = [
        generate_x25519_private_key,
        lambda: x25519_public_key(FakeXPrivate()),
        lambda: x25519_public_key_bytes(FakeXPublic()),
        lambda: x25519_public_key_from_bytes(b"0" * 32),
        lambda: derive_shared_secret(FakeXPrivate(), FakeXPublic()),
    ]
    expected_messages = [
        "key agreement key generation failed",
        "key agreement key invalid",
        "key agreement key invalid",
        "key agreement key invalid",
        "key agreement failed",
    ]
    for call, expected_message in zip(calls, expected_messages, strict=True):
        with pytest.raises(KeyAgreementError, match=f"^{expected_message}$"):
            call()


@pytest.mark.parametrize("fatal_error", [MemoryError, KeyboardInterrupt, SystemExit])
def test_fatal_library_errors_propagate(
    monkeypatch: pytest.MonkeyPatch, fatal_error: type[BaseException]
) -> None:
    class FatalXPrivate:
        @classmethod
        def generate(cls) -> "FatalXPrivate":
            raise fatal_error

    monkeypatch.setattr("saga.crypto.key_agreement.X25519PrivateKey", FatalXPrivate)
    with pytest.raises(fatal_error):
        generate_x25519_private_key()


def test_all_x25519_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/x25519-agreement.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    private_inputs = {
        "rfc7748-alice-bob": (
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        )
    }
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {"name", "alice_public_hex", "bob_public_hex", "shared_secret_hex"}
        name = row["name"]
        assert name in private_inputs and name not in seen
        seen.add(name)
        alice = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_inputs[name][0]))
        bob = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_inputs[name][1]))
        assert x25519_public_key_bytes(alice.public_key()).hex() == row["alice_public_hex"]
        assert x25519_public_key_bytes(bob.public_key()).hex() == row["bob_public_hex"]
        assert derive_shared_secret(alice, bob.public_key()).hex() == row["shared_secret_hex"]
        assert derive_shared_secret(bob, alice.public_key()).hex() == row["shared_secret_hex"]
    assert seen == set(private_inputs)
