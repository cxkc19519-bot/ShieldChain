import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from cryptography.exceptions import InvalidTag

from saga.crypto.aead import ActEnvelope, AeadError, decrypt_act, encrypt_act


def test_act_envelope_keeps_version_and_aead_nonce_outside_plaintext() -> None:
    key = bytes(range(32))
    plaintext = (
        b'{"nonce":"AA","issued_at":1,"expires_at":2,"q_max":1,'
        b'"initiating_agent_access_control_public_key":"AA"}'
    )
    outer_nonce = bytes(range(12))
    envelope = encrypt_act(key, plaintext, nonce=outer_nonce)
    assert envelope.version == 1
    assert envelope.nonce == outer_nonce
    assert envelope.ciphertext != plaintext
    assert decrypt_act(key, envelope) == plaintext


def test_encrypt_uses_fresh_random_nonces() -> None:
    key = bytes(range(32))
    plaintext = b"public fixture"
    first = encrypt_act(key, plaintext)
    second = encrypt_act(key, plaintext)
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_key_version_nonce_and_ciphertext_mutations_fail() -> None:
    key = bytes(range(32))
    envelope = encrypt_act(key, b"public fixture", nonce=bytes(range(12)))
    cases = (
        (bytes(reversed(range(32))), envelope),
        (key, replace(envelope, version=2)),
        (key, replace(envelope, nonce=bytes(reversed(range(12))))),
        (
            key,
            replace(
                envelope,
                ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]),
            ),
        ),
    )
    for candidate_key, candidate_envelope in cases:
        with pytest.raises(AeadError, match="ACT decryption failed"):
            decrypt_act(candidate_key, candidate_envelope)


def test_aad_domain_mismatch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    key = bytes(range(32))
    envelope = encrypt_act(key, b"public fixture", nonce=bytes(range(12)))
    monkeypatch.setattr("saga.crypto.aead.SAGA_ACT_AAD", b"SAGA-ACT/v2")
    with pytest.raises(AeadError, match="ACT decryption failed"):
        decrypt_act(key, envelope)


@pytest.mark.parametrize("key", [object(), b"", b"0" * 31, b"0" * 33])
def test_encrypt_rejects_bad_keys(key: object) -> None:
    with pytest.raises(AeadError):
        encrypt_act(key, b"p", nonce=b"0" * 12)


@pytest.mark.parametrize("plaintext", [object(), "p", bytearray(b"p")])
def test_encrypt_rejects_non_bytes_plaintext(plaintext: object) -> None:
    with pytest.raises(AeadError):
        encrypt_act(b"0" * 32, plaintext, nonce=b"0" * 12)


@pytest.mark.parametrize("version", [True, 1.0, "1", 2])
def test_decrypt_rejects_non_plain_one_version(version: object) -> None:
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(version, b"0" * 12, b"0" * 16))


@pytest.mark.parametrize("nonce", [object(), "n", b"", b"0" * 11, b"0" * 13])
def test_decrypt_rejects_bad_nonce(nonce: object) -> None:
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(1, nonce, b"0" * 16))


@pytest.mark.parametrize("ciphertext", [object(), "c", b"", b"0" * 15])
def test_decrypt_rejects_bad_ciphertext(ciphertext: object) -> None:
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(1, b"0" * 12, ciphertext))


def _raising(error: BaseException) -> Callable[[int], bytes]:
    def raise_error(_: int) -> bytes:
        raise error

    return raise_error


@pytest.mark.parametrize(
    "rng",
    [
        object(),
        lambda _: "x",
        lambda _: b"0" * 11,
        lambda _: b"0" * 13,
        _raising(TypeError()),
        _raising(ValueError()),
    ],
)
def test_rng_failures_are_normalized(rng: object) -> None:
    with pytest.raises(AeadError):
        encrypt_act(b"0" * 32, b"p", random_bytes=rng)


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_rng_system_exceptions_propagate(error: BaseException) -> None:
    with pytest.raises(type(error)):
        encrypt_act(b"0" * 32, b"p", random_bytes=_raising(error))


class FakeChaCha20Poly1305:
    mode = "ok"

    def __init__(self, _: bytes) -> None:
        if self.mode == "constructor-error":
            raise ValueError

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        del nonce, plaintext, aad
        if self.mode == "encrypt-error":
            raise TypeError
        if self.mode == "wrong-encrypt-return":
            return cast(bytes, object())
        return b"0" * 16

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        del nonce, ciphertext, aad
        if self.mode == "decrypt-error":
            raise InvalidTag
        if self.mode == "wrong-decrypt-return":
            return cast(bytes, object())
        return b"p"


@pytest.mark.parametrize("mode", ["constructor-error", "encrypt-error", "wrong-encrypt-return"])
def test_encrypt_library_failures(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    FakeChaCha20Poly1305.mode = mode
    monkeypatch.setattr("saga.crypto.aead.ChaCha20Poly1305", FakeChaCha20Poly1305)
    with pytest.raises(AeadError):
        encrypt_act(b"0" * 32, b"p", nonce=b"0" * 12)


@pytest.mark.parametrize("mode", ["constructor-error", "decrypt-error", "wrong-decrypt-return"])
def test_decrypt_library_failures(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    FakeChaCha20Poly1305.mode = mode
    monkeypatch.setattr("saga.crypto.aead.ChaCha20Poly1305", FakeChaCha20Poly1305)
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(1, b"0" * 12, b"0" * 16))


def test_failures_use_fixed_messages_without_secret_material() -> None:
    key = b"K" * 32
    plaintext = b"sensitive plaintext"
    with pytest.raises(AeadError) as encryption_error:
        encrypt_act(key, plaintext, nonce=b"short")
    assert str(encryption_error.value) == "ACT encryption input invalid"
    assert key.hex() not in str(encryption_error.value)
    assert plaintext.decode() not in str(encryption_error.value)

    ciphertext = b"C" * 16
    with pytest.raises(AeadError) as decryption_error:
        decrypt_act(key, ActEnvelope(1, b"N" * 12, ciphertext))
    assert str(decryption_error.value) == "ACT decryption failed"
    assert key.hex() not in str(decryption_error.value)
    assert ciphertext.hex() not in str(decryption_error.value)


def test_all_aead_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/chacha20-poly1305.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    assert document["format_version"] == 1
    inputs = {"range-key": bytes(range(32))}
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {
            "name",
            "outer_nonce_hex",
            "plaintext_hex",
            "aad_ascii",
            "ciphertext_and_tag_hex",
        }
        name = row["name"]
        assert name in inputs and name not in seen and row["aad_ascii"] == "SAGA-ACT/v1"
        seen.add(name)
        nonce = bytes.fromhex(row["outer_nonce_hex"])
        plaintext = bytes.fromhex(row["plaintext_hex"])
        ciphertext = bytes.fromhex(row["ciphertext_and_tag_hex"])
        envelope = encrypt_act(inputs[name], plaintext, nonce=nonce)
        assert envelope.ciphertext == ciphertext
        assert decrypt_act(inputs[name], envelope) == plaintext
        for changed in (
            replace(envelope, nonce=nonce[:-1] + bytes([nonce[-1] ^ 1])),
            replace(
                envelope,
                ciphertext=ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]),
            ),
        ):
            with pytest.raises(AeadError):
                decrypt_act(inputs[name], changed)
    assert seen == set(inputs)
