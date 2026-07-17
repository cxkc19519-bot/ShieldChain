"""Concrete adapters for the Phase 1 cryptographic primitives."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.crypto.signatures import ed25519_public_key, ed25519_public_key_bytes, sign


class Ed25519ProviderSigner:
    """Provider-signing adapter that keeps its private key out of DTOs and reprs."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("provider signer key invalid")
        self._private_key = private_key

    def public_key_bytes(self) -> bytes:
        return ed25519_public_key_bytes(ed25519_public_key(self._private_key))

    def sign(self, message: bytes) -> bytes:
        return sign(self._private_key, message)

    def __repr__(self) -> str:
        return "Ed25519ProviderSigner(redacted=True)"


__all__ = ("Ed25519ProviderSigner",)
