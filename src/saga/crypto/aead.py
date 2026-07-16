import secrets
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class AeadError(ValueError):
    """An ACT envelope is invalid or unauthentic."""


SAGA_ACT_AAD = b"SAGA-ACT/v1"
SAGA_ACT_ENVELOPE_VERSION = 1
CHACHA_NONCE_BYTES = 12


@dataclass(frozen=True, slots=True)
class ActEnvelope:
    version: int
    nonce: bytes
    ciphertext: bytes


def encrypt_act(
    key: bytes,
    plaintext: bytes,
    *,
    nonce: bytes | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> ActEnvelope:
    try:
        if type(key) is not bytes or len(key) != 32 or type(plaintext) is not bytes:
            raise AeadError("ACT encryption input invalid")
        if nonce is None:
            if not callable(random_bytes):
                raise AeadError("ACT encryption input invalid")
            outer_nonce = random_bytes(CHACHA_NONCE_BYTES)
        else:
            outer_nonce = nonce
        if type(outer_nonce) is not bytes or len(outer_nonce) != CHACHA_NONCE_BYTES:
            raise AeadError("ACT encryption input invalid")
        primitive = ChaCha20Poly1305(key)
        ciphertext = primitive.encrypt(outer_nonce, plaintext, SAGA_ACT_AAD)
        if type(ciphertext) is not bytes or len(ciphertext) < 16:
            raise AeadError("ACT encryption input invalid")
        return ActEnvelope(SAGA_ACT_ENVELOPE_VERSION, outer_nonce, ciphertext)
    except AeadError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise AeadError("ACT encryption input invalid") from None


def decrypt_act(key: bytes, envelope: ActEnvelope) -> bytes:
    try:
        if (
            type(key) is not bytes
            or len(key) != 32
            or not isinstance(envelope, ActEnvelope)
            or type(envelope.version) is not int
            or envelope.version != SAGA_ACT_ENVELOPE_VERSION
            or type(envelope.nonce) is not bytes
            or len(envelope.nonce) != CHACHA_NONCE_BYTES
            or type(envelope.ciphertext) is not bytes
            or len(envelope.ciphertext) < 16
        ):
            raise AeadError("ACT decryption failed")
        primitive = ChaCha20Poly1305(key)
        plaintext = primitive.decrypt(envelope.nonce, envelope.ciphertext, SAGA_ACT_AAD)
        if type(plaintext) is not bytes:
            raise AeadError("ACT decryption failed")
        return plaintext
    except AeadError:
        raise
    except (AttributeError, InvalidTag, TypeError, ValueError):
        raise AeadError("ACT decryption failed") from None
