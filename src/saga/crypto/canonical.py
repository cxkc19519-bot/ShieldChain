import json
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeGuard

from saga.domain.encoding import (
    EncodingError,
    EndpointValue,
    b64url_decode,
    b64url_encode,
    require_unix_ms,
)


class CanonicalEncodingError(EncodingError):
    """A JSON object does not match its closed canonical schema."""


CanonicalKind = Literal["text", "integer", "unix_ms", "bytes", "endpoint"]
CanonicalDecodedValue = str | int | bytes | EndpointValue


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    kind: CanonicalKind


class _ObjectPairs(list[tuple[str, object]]):
    """Duplicate-preserving marker for a JSON object, distinct from arrays."""


def _pairs_hook(items: list[tuple[str, object]]) -> _ObjectPairs:
    return _ObjectPairs(items)


def _valid_text(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(unicodedata.category(c) == "Cc" for c in value)
    )


def _encode_value(value: object, kind: CanonicalKind) -> object:
    if kind == "text":
        if not _valid_text(value):
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "integer":
        if type(value) is not int:
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "unix_ms":
        try:
            return require_unix_ms(value, "canonical time")
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "bytes":
        if type(value) is not bytes:
            raise CanonicalEncodingError("canonical value invalid")
        try:
            return b64url_encode(value)
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "endpoint":
        if not isinstance(value, EndpointValue):
            raise CanonicalEncodingError("canonical value invalid")
        return value.as_canonical_value()
    raise CanonicalEncodingError("canonical schema invalid")


def _decode_endpoint(value: object) -> EndpointValue:
    if not isinstance(value, _ObjectPairs):
        raise CanonicalEncodingError("canonical value invalid")
    names = tuple(name for name, _ in value)
    if names != ("device", "ip", "port") or len(set(names)) != 3:
        raise CanonicalEncodingError("canonical value invalid")
    device, ip, port = (item for _, item in value)
    if not _valid_text(device) or not isinstance(ip, str) or type(port) is not int:
        raise CanonicalEncodingError("canonical value invalid")
    try:
        return EndpointValue(device=device, ip=ip, port=port)
    except EncodingError:
        raise CanonicalEncodingError("canonical value invalid") from None


def _decode_value(value: object, kind: CanonicalKind) -> CanonicalDecodedValue:
    if kind == "text":
        if not _valid_text(value):
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "integer":
        if type(value) is not int:
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "unix_ms":
        try:
            return require_unix_ms(value, "canonical time")
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "bytes":
        if not isinstance(value, str):
            raise CanonicalEncodingError("canonical value invalid")
        try:
            return b64url_decode(value)
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "endpoint":
        return _decode_endpoint(value)
    raise CanonicalEncodingError("canonical schema invalid")


def canonical_object_bytes(values: Mapping[str, object], schema: tuple[FieldSpec, ...]) -> bytes:
    try:
        expected = tuple(field.name for field in schema)
        if (
            len(set(expected)) != len(expected)
            or len(values) != len(expected)
            or set(values.keys()) != set(expected)
        ):
            raise CanonicalEncodingError("canonical fields invalid")
        encoded = {field.name: _encode_value(values[field.name], field.kind) for field in schema}
        return json.dumps(
            encoded, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except CanonicalEncodingError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CanonicalEncodingError("canonical JSON invalid") from None


def parse_canonical_object(
    data: bytes, schema: tuple[FieldSpec, ...]
) -> dict[str, CanonicalDecodedValue]:
    try:
        if not isinstance(data, bytes):
            raise CanonicalEncodingError("canonical JSON invalid")
        pairs = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_hook)
        if not isinstance(pairs, _ObjectPairs):
            raise CanonicalEncodingError("canonical JSON invalid")
        names = tuple(name for name, _ in pairs)
        expected = tuple(field.name for field in schema)
        if names != expected or len(set(names)) != len(names):
            raise CanonicalEncodingError("canonical fields invalid")
        result = {
            field.name: _decode_value(raw, field.kind)
            for field, (_, raw) in zip(schema, pairs, strict=True)
        }
        if canonical_object_bytes(result, schema) != data:
            raise CanonicalEncodingError("canonical JSON invalid")
        return result
    except CanonicalEncodingError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CanonicalEncodingError("canonical JSON invalid") from None
