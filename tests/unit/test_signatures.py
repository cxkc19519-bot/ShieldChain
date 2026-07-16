import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.crypto.canonical import (
    OtkAttestation,
    decode_otk_attestation,
    encode_otk_attestation,
)
from saga.crypto.signatures import (
    SignatureError,
    ed25519_public_key,
    ed25519_public_key_bytes,
    ed25519_public_key_from_bytes,
    generate_ed25519_private_key,
    sign,
    verify,
)


def test_rfc8032_vector_one() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    signature = sign(private_key, b"")
    public = ed25519_public_key(private_key)
    public_raw = ed25519_public_key_bytes(public)
    assert public_raw.hex() == ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    assert signature.hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519_public_key_bytes(ed25519_public_key_from_bytes(public_raw)) == public_raw
    verify(public, b"", signature)


def test_any_signed_input_mutation_fails() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    message = b'{"agent_id":"alice:worker","one_time_public_key":"AA"}'
    signature = sign(private_key, message)
    bad_signature = signature[:-1] + bytes([signature[-1] ^ 1])
    for public_key, candidate_message, candidate_signature in (
        (private_key.public_key(), message + b" ", signature),
        (private_key.public_key(), message, bad_signature),
        (other_key.public_key(), message, signature),
    ):
        with pytest.raises(SignatureError, match="signature verification failed"):
            verify(public_key, candidate_message, candidate_signature)


def test_same_type_tuple_mutation_parses_but_breaks_signature() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    original = encode_otk_attestation(OtkAttestation("alice:worker", bytes(range(32))))
    changed_value = OtkAttestation("alice:worker", bytes(range(1, 33)))
    changed = encode_otk_attestation(changed_value)
    assert decode_otk_attestation(changed) == changed_value
    with pytest.raises(SignatureError):
        verify(private.public_key(), changed, sign(private, original))


def test_signature_wrong_objects_and_lengths_fail() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    calls = [
        lambda: ed25519_public_key(object()),
        lambda: ed25519_public_key_bytes(object()),
        lambda: ed25519_public_key_from_bytes(object()),
        lambda: sign(object(), b"m"),
        lambda: sign(private, "m"),
        lambda: verify(object(), b"m", b"0" * 64),
        lambda: verify(public, "m", b"0" * 64),
        lambda: verify(public, b"m", object()),
    ]
    calls.extend(lambda n=n: ed25519_public_key_from_bytes(b"0" * n) for n in (0, 31, 33))
    calls.extend(lambda n=n: verify(public, b"m", b"0" * n) for n in (0, 63, 65))
    for call in calls:
        with pytest.raises(SignatureError):
            call()


class FakeEdPublic:
    @classmethod
    def from_public_bytes(cls, _: bytes) -> "FakeEdPublic":
        raise ValueError

    def public_bytes(self, *_: object) -> bytes:
        raise TypeError

    def verify(self, *_: object) -> None:
        raise InvalidSignature


class FakeEdPrivate:
    @classmethod
    def generate(cls) -> "FakeEdPrivate":
        raise ValueError

    def public_key(self) -> FakeEdPublic:
        raise TypeError

    def sign(self, _: bytes) -> bytes:
        raise ValueError


def test_signature_library_errors_are_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("saga.crypto.signatures.Ed25519PrivateKey", FakeEdPrivate)
    monkeypatch.setattr("saga.crypto.signatures.Ed25519PublicKey", FakeEdPublic)
    calls = [
        generate_ed25519_private_key,
        lambda: ed25519_public_key(FakeEdPrivate()),
        lambda: ed25519_public_key_bytes(FakeEdPublic()),
        lambda: ed25519_public_key_from_bytes(b"0" * 32),
        lambda: sign(FakeEdPrivate(), b"m"),
        lambda: verify(FakeEdPublic(), b"m", b"0" * 64),
    ]
    for call in calls:
        with pytest.raises(SignatureError):
            call()


def test_all_signature_vectors_are_consumed() -> None:
    signature_doc = json.loads(Path("tests/vectors/ed25519-signatures.json").read_text("utf-8"))
    canonical_doc = json.loads(Path("tests/vectors/canonical-tuples.json").read_text("utf-8"))
    messages = {
        row["name"]: bytes.fromhex(row["canonical_utf8_hex"]) for row in canonical_doc["vectors"]
    }
    assert set(signature_doc) == {"format_version", "vectors"}
    seen: set[str] = set()
    for row in signature_doc["vectors"]:
        assert set(row) == {
            "name",
            "source",
            "public_key_hex",
            "message_vector_name",
            "signature_hex",
        }
        assert row["name"] == row["message_vector_name"] and row["name"] not in seen
        seen.add(row["name"])
        public = ed25519_public_key_from_bytes(bytes.fromhex(row["public_key_hex"]))
        signature = bytes.fromhex(row["signature_hex"])
        message = messages[row["message_vector_name"]]
        verify(public, message, signature)
        with pytest.raises(SignatureError):
            verify(public, message[:-1] + bytes([message[-1] ^ 1]), signature)
        with pytest.raises(SignatureError):
            verify(public, message, signature[:-1] + bytes([signature[-1] ^ 1]))
    assert seen == {"agent_user", "otk", "provider"}
