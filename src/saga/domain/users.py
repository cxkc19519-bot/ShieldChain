import unicodedata
from dataclasses import dataclass

from .errors import InvalidRegistrationInput


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise InvalidRegistrationInput() from None


def _valid_identifier(value: object, *, max_bytes: int) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and ":" not in value
        and not any(unicodedata.category(character) == "Cc" for character in value)
        and _utf8_length(value) <= max_bytes
    )


def _require_certificate(value: object) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= 16_384:
        raise InvalidRegistrationInput()
    return value


def _require_password(value: object) -> str:
    if type(value) is not str or not value or not 1 <= _utf8_length(value) <= 1_024:
        raise InvalidRegistrationInput()
    return value


@dataclass(frozen=True, slots=True)
class UserId:
    value: str

    def __post_init__(self) -> None:
        if not _valid_identifier(self.value, max_bytes=254):
            raise InvalidRegistrationInput()


@dataclass(frozen=True, slots=True, repr=False)
class StoredPasswordRecord:
    version: int
    n: int
    r: int
    p: int
    dklen: int
    salt: bytes
    verifier: bytes

    def __post_init__(self) -> None:
        if not (
            type(self.version) is int
            and self.version == 1
            and type(self.n) is int
            and self.n == 2**15
            and type(self.r) is int
            and self.r == 8
            and type(self.p) is int
            and self.p == 1
            and type(self.dklen) is int
            and self.dklen == 32
            and type(self.salt) is bytes
            and len(self.salt) == 16
            and type(self.verifier) is bytes
            and len(self.verifier) == 32
        ):
            raise InvalidRegistrationInput()

    def __repr__(self) -> str:
        return "StoredPasswordRecord(version=1, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class UserRegistration:
    user_id: UserId
    password_record: StoredPasswordRecord
    certificate_der: bytes

    def __post_init__(self) -> None:
        if (
            type(self.user_id) is not UserId
            or type(self.password_record) is not StoredPasswordRecord
        ):
            raise InvalidRegistrationInput()
        _require_certificate(self.certificate_der)

    def __repr__(self) -> str:
        return f"UserRegistration(user_id={self.user_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class RegisterUserCommand:
    user_id: UserId
    password: str
    certificate_der: bytes

    def __post_init__(self) -> None:
        if type(self.user_id) is not UserId:
            raise InvalidRegistrationInput()
        _require_password(self.password)
        _require_certificate(self.certificate_der)

    def __repr__(self) -> str:
        return f"RegisterUserCommand(user_id={self.user_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class UserRegistered:
    user_id: UserId

    def __post_init__(self) -> None:
        if type(self.user_id) is not UserId:
            raise InvalidRegistrationInput()


__all__ = (
    "RegisterUserCommand",
    "StoredPasswordRecord",
    "UserId",
    "UserRegistered",
    "UserRegistration",
)
