from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SAGA_HKDF_INFO = b"SAGA-ACT-DERIVE/v1"
SAGA_KEY_BYTES = 32


class KeyDerivationError(ValueError):
    """A SAGA KDF input is invalid."""


def derive_sdhk(shared_secret: bytes) -> bytes:
    """Derive the 32-byte SAGA ACT key with fixed salt/info."""
    if type(shared_secret) is not bytes or len(shared_secret) != 32:
        raise KeyDerivationError("key derivation input invalid")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=SAGA_HKDF_INFO,
    ).derive(shared_secret)
