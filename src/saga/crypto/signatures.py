from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class SignatureError(ValueError):
    """Signature input or verification is invalid."""


def generate_ed25519_private_key() -> Ed25519PrivateKey:
    try:
        key = Ed25519PrivateKey.generate()
    except (TypeError, ValueError):
        raise SignatureError("signature key generation failed") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("signature key generation failed")
    return key


def ed25519_public_key(key: Ed25519PrivateKey) -> Ed25519PublicKey:
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("signature key invalid")
    try:
        public = key.public_key()
    except (TypeError, ValueError):
        raise SignatureError("signature key invalid") from None
    if not isinstance(public, Ed25519PublicKey):
        raise SignatureError("signature key invalid")
    return public


def ed25519_public_key_bytes(key: Ed25519PublicKey) -> bytes:
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("signature key invalid")
    try:
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (TypeError, ValueError):
        raise SignatureError("signature key invalid") from None
    if type(raw) is not bytes or len(raw) != 32:
        raise SignatureError("signature key invalid")
    return raw


def ed25519_public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    if type(data) is not bytes or len(data) != 32:
        raise SignatureError("signature key invalid")
    try:
        return Ed25519PublicKey.from_public_bytes(data)
    except (TypeError, ValueError):
        raise SignatureError("signature key invalid") from None


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    if not isinstance(private_key, Ed25519PrivateKey) or type(message) is not bytes:
        raise SignatureError("signature input invalid")
    try:
        signature = private_key.sign(message)
    except (TypeError, ValueError):
        raise SignatureError("signature input invalid") from None
    if type(signature) is not bytes or len(signature) != 64:
        raise SignatureError("signature input invalid")
    return signature


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> None:
    if (
        not isinstance(public_key, Ed25519PublicKey)
        or type(message) is not bytes
        or type(signature) is not bytes
        or len(signature) != 64
    ):
        raise SignatureError("signature verification failed")
    try:
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        raise SignatureError("signature verification failed") from None
