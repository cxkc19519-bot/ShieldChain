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


AGENT_USER_ATTESTATION_SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("endpoint", "endpoint"),
    FieldSpec("agent_tls_public_key", "bytes"),
    FieldSpec("agent_access_control_public_key", "bytes"),
    FieldSpec("provider_public_key", "bytes"),
)
OTK_ATTESTATION_SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("one_time_public_key", "bytes"),
)
PROVIDER_ATTESTATION_SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("agent_certificate", "bytes"),
    FieldSpec("endpoint", "endpoint"),
    FieldSpec("agent_access_control_public_key", "bytes"),
    FieldSpec("user_signature", "bytes"),
)
ACT_PLAINTEXT_SCHEMA = (
    FieldSpec("nonce", "bytes"),
    FieldSpec("issued_at", "unix_ms"),
    FieldSpec("expires_at", "unix_ms"),
    FieldSpec("q_max", "integer"),
    FieldSpec("initiating_agent_access_control_public_key", "bytes"),
)


@dataclass(frozen=True, slots=True)
class AgentUserAttestation:
    agent_id: str
    endpoint: EndpointValue
    agent_tls_public_key: bytes
    agent_access_control_public_key: bytes
    provider_public_key: bytes


@dataclass(frozen=True, slots=True)
class OtkAttestation:
    agent_id: str
    one_time_public_key: bytes


@dataclass(frozen=True, slots=True)
class ProviderAttestation:
    agent_id: str
    agent_certificate: bytes
    endpoint: EndpointValue
    agent_access_control_public_key: bytes
    user_signature: bytes


@dataclass(frozen=True, slots=True)
class ActPlaintext:
    nonce: bytes
    issued_at: int
    expires_at: int
    q_max: int
    initiating_agent_access_control_public_key: bytes


def _tuple_text(value: object) -> str:
    if not _valid_text(value):
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def _tuple_bytes(value: object, length: int | None = None) -> bytes:
    if type(value) is not bytes or not value:
        raise CanonicalEncodingError("protocol tuple invalid")
    if length is not None and len(value) != length:
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def _tuple_endpoint(value: object) -> EndpointValue:
    if not isinstance(value, EndpointValue):
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def _tuple_int(value: object, *, unix_ms: bool = False) -> int:
    if type(value) is not int or (unix_ms and value < 0):
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def encode_agent_user_attestation(value: AgentUserAttestation) -> bytes:
    try:
        if not isinstance(value, AgentUserAttestation):
            raise CanonicalEncodingError("protocol tuple invalid")
        fields: dict[str, object] = {
            "agent_id": _tuple_text(value.agent_id),
            "endpoint": _tuple_endpoint(value.endpoint),
            "agent_tls_public_key": _tuple_bytes(value.agent_tls_public_key),
            "agent_access_control_public_key": _tuple_bytes(
                value.agent_access_control_public_key, 32
            ),
            "provider_public_key": _tuple_bytes(value.provider_public_key, 32),
        }
        return canonical_object_bytes(fields, AGENT_USER_ATTESTATION_SCHEMA)
    except CanonicalEncodingError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise CanonicalEncodingError("protocol tuple invalid") from None


def decode_agent_user_attestation(data: bytes) -> AgentUserAttestation:
    try:
        values = parse_canonical_object(data, AGENT_USER_ATTESTATION_SCHEMA)
        return AgentUserAttestation(
            agent_id=_tuple_text(values["agent_id"]),
            endpoint=_tuple_endpoint(values["endpoint"]),
            agent_tls_public_key=_tuple_bytes(values["agent_tls_public_key"]),
            agent_access_control_public_key=_tuple_bytes(
                values["agent_access_control_public_key"], 32
            ),
            provider_public_key=_tuple_bytes(values["provider_public_key"], 32),
        )
    except CanonicalEncodingError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CanonicalEncodingError("protocol tuple invalid") from None


def encode_otk_attestation(value: OtkAttestation) -> bytes:
    if not isinstance(value, OtkAttestation):
        raise CanonicalEncodingError("protocol tuple invalid")
    return canonical_object_bytes(
        {
            "agent_id": _tuple_text(value.agent_id),
            "one_time_public_key": _tuple_bytes(value.one_time_public_key, 32),
        },
        OTK_ATTESTATION_SCHEMA,
    )


def decode_otk_attestation(data: bytes) -> OtkAttestation:
    values = parse_canonical_object(data, OTK_ATTESTATION_SCHEMA)
    return OtkAttestation(
        agent_id=_tuple_text(values["agent_id"]),
        one_time_public_key=_tuple_bytes(values["one_time_public_key"], 32),
    )


def encode_provider_attestation(value: ProviderAttestation) -> bytes:
    if not isinstance(value, ProviderAttestation):
        raise CanonicalEncodingError("protocol tuple invalid")
    return canonical_object_bytes(
        {
            "agent_id": _tuple_text(value.agent_id),
            "agent_certificate": _tuple_bytes(value.agent_certificate),
            "endpoint": _tuple_endpoint(value.endpoint),
            "agent_access_control_public_key": _tuple_bytes(
                value.agent_access_control_public_key, 32
            ),
            "user_signature": _tuple_bytes(value.user_signature, 64),
        },
        PROVIDER_ATTESTATION_SCHEMA,
    )


def decode_provider_attestation(data: bytes) -> ProviderAttestation:
    values = parse_canonical_object(data, PROVIDER_ATTESTATION_SCHEMA)
    return ProviderAttestation(
        agent_id=_tuple_text(values["agent_id"]),
        agent_certificate=_tuple_bytes(values["agent_certificate"]),
        endpoint=_tuple_endpoint(values["endpoint"]),
        agent_access_control_public_key=_tuple_bytes(values["agent_access_control_public_key"], 32),
        user_signature=_tuple_bytes(values["user_signature"], 64),
    )


def encode_act_plaintext(value: ActPlaintext) -> bytes:
    if not isinstance(value, ActPlaintext):
        raise CanonicalEncodingError("protocol tuple invalid")
    return canonical_object_bytes(
        {
            "nonce": _tuple_bytes(value.nonce),
            "issued_at": _tuple_int(value.issued_at, unix_ms=True),
            "expires_at": _tuple_int(value.expires_at, unix_ms=True),
            "q_max": _tuple_int(value.q_max),
            "initiating_agent_access_control_public_key": _tuple_bytes(
                value.initiating_agent_access_control_public_key, 32
            ),
        },
        ACT_PLAINTEXT_SCHEMA,
    )


def decode_act_plaintext(data: bytes) -> ActPlaintext:
    values = parse_canonical_object(data, ACT_PLAINTEXT_SCHEMA)
    return ActPlaintext(
        nonce=_tuple_bytes(values["nonce"]),
        issued_at=_tuple_int(values["issued_at"], unix_ms=True),
        expires_at=_tuple_int(values["expires_at"], unix_ms=True),
        q_max=_tuple_int(values["q_max"]),
        initiating_agent_access_control_public_key=_tuple_bytes(
            values["initiating_agent_access_control_public_key"], 32
        ),
    )
