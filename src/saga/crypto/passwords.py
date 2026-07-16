import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeGuard

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__all__ = (
    "PasswordRecord",
    "PasswordRecordError",
    "hash_password",
    "verify_password",
)


class PasswordRecordError(ValueError):
    """A password record is malformed."""


@dataclass(frozen=True, slots=True, repr=False)
class PasswordRecord:
    version: int
    n: int
    r: int
    p: int
    dklen: int
    salt: bytes
    verifier: bytes

    def __repr__(self) -> str:
        return "PasswordRecord(version=1, redacted=True)"


def hash_password(
    password: str,
    *,
    salt: bytes | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> PasswordRecord:
    try:
        if not isinstance(password, str) or not password:
            raise PasswordRecordError("password input invalid")
        password_bytes = password.encode("utf-8", errors="strict")
        if salt is None:
            if not callable(random_bytes):
                raise PasswordRecordError("password record invalid")
            selected_salt = random_bytes(16)
        else:
            selected_salt = salt
        if type(selected_salt) is not bytes or len(selected_salt) != 16:
            raise PasswordRecordError("password record invalid")
        primitive = Scrypt(salt=selected_salt, length=32, n=2**15, r=8, p=1)
        verifier = primitive.derive(password_bytes)
        if type(verifier) is not bytes or len(verifier) != 32:
            raise PasswordRecordError("password record invalid")
        return PasswordRecord(1, 2**15, 8, 1, 32, selected_salt, verifier)
    except PasswordRecordError:
        raise
    except (OverflowError, TypeError, UnsupportedAlgorithm, ValueError):
        raise PasswordRecordError("password record invalid") from None


def _valid_record(record: object) -> TypeGuard[PasswordRecord]:
    return (
        isinstance(record, PasswordRecord)
        and type(record.version) is int
        and record.version == 1
        and type(record.n) is int
        and record.n == 2**15
        and type(record.r) is int
        and record.r == 8
        and type(record.p) is int
        and record.p == 1
        and type(record.dklen) is int
        and record.dklen == 32
        and type(record.salt) is bytes
        and len(record.salt) == 16
        and type(record.verifier) is bytes
        and len(record.verifier) == 32
    )


def verify_password(password: str, record: PasswordRecord) -> bool:
    try:
        if not isinstance(password, str) or not password or not _valid_record(record):
            raise PasswordRecordError("password record invalid")
        password_bytes = password.encode("utf-8", errors="strict")
        primitive = Scrypt(
            salt=record.salt, length=record.dklen, n=record.n, r=record.r, p=record.p
        )
        candidate = primitive.derive(password_bytes)
        if type(candidate) is not bytes or len(candidate) != 32:
            raise PasswordRecordError("password record invalid")
        return hmac.compare_digest(candidate, record.verifier)
    except PasswordRecordError:
        raise
    except (OverflowError, TypeError, UnsupportedAlgorithm, ValueError):
        raise PasswordRecordError("password record invalid") from None
