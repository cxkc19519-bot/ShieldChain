import base64
import ipaddress
import re
import unicodedata
from dataclasses import dataclass


class EncodingError(ValueError):
    """A public value is not in the single accepted encoding."""


@dataclass(frozen=True, slots=True)
class EndpointValue:
    device: str
    ip: str
    port: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.device, str)
            or not self.device
            or any(unicodedata.category(c) == "Cc" for c in self.device)
        ):
            raise EncodingError("invalid endpoint")
        if not isinstance(self.ip, str) or not self.ip or "%" in self.ip:
            raise EncodingError("invalid endpoint")
        try:
            parsed_ip = ipaddress.ip_address(self.ip)
        except ValueError:
            raise EncodingError("invalid endpoint") from None
        if parsed_ip.compressed != self.ip:
            raise EncodingError("invalid endpoint")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise EncodingError("invalid endpoint")

    def as_canonical_value(self) -> dict[str, str | int]:
        return {"device": self.device, "ip": self.ip, "port": self.port}


def b64url_encode(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise EncodingError("invalid binary value")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or "=" in value or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise EncodingError("invalid Base64URL")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise EncodingError("invalid Base64URL") from None
    if b64url_encode(decoded) != value:
        raise EncodingError("invalid Base64URL")
    return decoded


def require_unix_ms(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EncodingError("invalid Unix milliseconds")
    return value
