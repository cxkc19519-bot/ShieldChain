from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class KeyAgreementError(ValueError):
    """An X25519 input or exchange is invalid."""


def generate_x25519_private_key() -> X25519PrivateKey:
    try:
        key = X25519PrivateKey.generate()
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key generation failed") from None
    if not isinstance(key, X25519PrivateKey):
        raise KeyAgreementError("key agreement key generation failed")
    return key


def x25519_public_key(key: X25519PrivateKey) -> X25519PublicKey:
    if not isinstance(key, X25519PrivateKey):
        raise KeyAgreementError("key agreement key invalid")
    try:
        public = key.public_key()
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key invalid") from None
    if not isinstance(public, X25519PublicKey):
        raise KeyAgreementError("key agreement key invalid")
    return public


def x25519_public_key_bytes(key: X25519PublicKey) -> bytes:
    if not isinstance(key, X25519PublicKey):
        raise KeyAgreementError("key agreement key invalid")
    try:
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key invalid") from None
    if type(raw) is not bytes or len(raw) != 32:
        raise KeyAgreementError("key agreement key invalid")
    return raw


def x25519_public_key_from_bytes(data: bytes) -> X25519PublicKey:
    if type(data) is not bytes or len(data) != 32:
        raise KeyAgreementError("key agreement key invalid")
    try:
        return X25519PublicKey.from_public_bytes(data)
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key invalid") from None


def derive_shared_secret(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    if not isinstance(private_key, X25519PrivateKey) or not isinstance(
        peer_public_key, X25519PublicKey
    ):
        raise KeyAgreementError("key agreement failed")
    try:
        shared = private_key.exchange(peer_public_key)
    except (ValueError, TypeError):
        raise KeyAgreementError("key agreement failed") from None
    if type(shared) is not bytes or len(shared) != 32 or not any(shared):
        raise KeyAgreementError("key agreement failed")
    return shared
