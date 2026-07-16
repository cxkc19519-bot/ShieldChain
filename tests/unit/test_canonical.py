import pytest

from saga.crypto.canonical import (
    CanonicalEncodingError,
    FieldSpec,
    canonical_object_bytes,
    parse_canonical_object,
)

SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("issued_at", "unix_ms"),
    FieldSpec("public_key", "bytes"),
)

ENDPOINT_SCHEMA = (FieldSpec("endpoint", "endpoint"),)


def test_canonical_bytes_are_ordered_compact_utf8() -> None:
    encoded = canonical_object_bytes(
        {"public_key": b"\x00\xff", "issued_at": 7, "agent_id": "代理-A"},
        SCHEMA,
    )
    assert encoded == (
        b'{"agent_id":"\xe4\xbb\xa3\xe7\x90\x86-A","issued_at":7,"public_key":"AP8"}'
    )
    assert canonical_object_bytes(parse_canonical_object(encoded, SCHEMA), SCHEMA) == encoded


@pytest.mark.parametrize(
    "payload",
    [
        b'{"agent_id":"a","agent_id":"b","issued_at":7,"public_key":"AA"}',
        b'{"agent_id":"a","issued_at":7,"public_key":"AA","extra":1}',
        b'{"issued_at":7,"agent_id":"a","public_key":"AA"}',
        b'{"agent_id":"a","issued_at":7.0,"public_key":"AA"}',
        b'{"agent_id":"a","issued_at":true,"public_key":"AA"}',
        b"[]",
        b'{"agent_id":"a","issued_at":7,"public_key":0}',
    ],
)
def test_parser_rejects_duplicates_unknowns_wrong_order_and_float(payload: bytes) -> None:
    with pytest.raises(CanonicalEncodingError):
        parse_canonical_object(payload, SCHEMA)


def test_encoder_accepts_unordered_mapping_but_emits_schema_order() -> None:
    values = {"public_key": b"\x00", "agent_id": "a", "issued_at": 7}
    assert tuple(values) != tuple(field.name for field in SCHEMA)
    assert canonical_object_bytes(values, SCHEMA) == (
        b'{"agent_id":"a","issued_at":7,"public_key":"AA"}'
    )


@pytest.mark.parametrize(
    ("payload", "schema"),
    [
        (b"[]", SCHEMA),
        (b'"x"', SCHEMA),
        (b"1", SCHEMA),
        (b"null", SCHEMA),
        (b'{"agent_id":"a","agent_id":"b","issued_at":1,"public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":1,"public_key":"AA","x":0}', SCHEMA),
        (b'{"issued_at":1,"agent_id":"a","public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":true,"public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":1.0,"public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":1,"public_key":"AA="}', SCHEMA),
        (
            b'{"endpoint":{"device":"d","device":"e","ip":"192.0.2.1","port":1}}',
            ENDPOINT_SCHEMA,
        ),
        (b'{"endpoint":{"ip":"192.0.2.1","device":"d","port":1}}', ENDPOINT_SCHEMA),
        (
            b'{"endpoint":{"device":"d","ip":"192.0.2.1","port":1,"x":0}}',
            ENDPOINT_SCHEMA,
        ),
        (b'{"endpoint":{"device":"d","ip":"192.0.2.1","port":true}}', ENDPOINT_SCHEMA),
        (b"\xff", SCHEMA),
    ],
)
def test_all_canonical_negative_cases(payload: bytes, schema: tuple[FieldSpec, ...]) -> None:
    with pytest.raises(CanonicalEncodingError):
        parse_canonical_object(payload, schema)


@pytest.mark.parametrize("control", ["\x00", "\x7f", "\u0085"])
def test_all_unicode_cc_text_is_rejected(control: str) -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical_object_bytes(
            {"agent_id": f"a{control}", "issued_at": 1, "public_key": b""}, SCHEMA
        )
