import json
import subprocess
import sys
from pathlib import Path

import pytest

from saga.crypto.canonical import (
    ACT_PLAINTEXT_SCHEMA,
    AGENT_USER_ATTESTATION_SCHEMA,
    OTK_ATTESTATION_SCHEMA,
    PROVIDER_ATTESTATION_SCHEMA,
    ActPlaintext,
    AgentUserAttestation,
    CanonicalEncodingError,
    OtkAttestation,
    ProviderAttestation,
    decode_act_plaintext,
    decode_agent_user_attestation,
    decode_otk_attestation,
    decode_provider_attestation,
    encode_act_plaintext,
    encode_agent_user_attestation,
    encode_otk_attestation,
    encode_provider_attestation,
)
from saga.domain.encoding import EndpointValue, b64url_decode

VECTOR_PATH = Path("tests/vectors/canonical-tuples.json")


def _tagged_bytes(value: object) -> bytes:
    assert isinstance(value, dict)
    assert set(value) == {"encoding", "value"}
    assert value["encoding"] == "base64url"
    assert isinstance(value["value"], str)
    return b64url_decode(value["value"])


def test_paper_tuple_field_orders_are_exact() -> None:
    assert tuple(field.name for field in AGENT_USER_ATTESTATION_SCHEMA) == (
        "agent_id",
        "endpoint",
        "agent_tls_public_key",
        "agent_access_control_public_key",
        "provider_public_key",
    )
    assert tuple(field.name for field in OTK_ATTESTATION_SCHEMA) == (
        "agent_id",
        "one_time_public_key",
    )
    assert tuple(field.name for field in PROVIDER_ATTESTATION_SCHEMA) == (
        "agent_id",
        "agent_certificate",
        "endpoint",
        "agent_access_control_public_key",
        "user_signature",
    )
    assert tuple(field.name for field in ACT_PLAINTEXT_SCHEMA) == (
        "nonce",
        "issued_at",
        "expires_at",
        "q_max",
        "initiating_agent_access_control_public_key",
    )


def test_public_act_vector_is_byte_exact() -> None:
    value = ActPlaintext(
        nonce=bytes(range(16)),
        issued_at=1,
        expires_at=2,
        q_max=3,
        initiating_agent_access_control_public_key=bytes(range(32)),
    )
    encoded = encode_act_plaintext(value)
    expected = bytes.fromhex(
        "7b226e6f6e6365223a2241414543417751464267634943516f4c4441304f4477222c"
        "226973737565645f6174223a312c22657870697265735f6174223a322c22715f6d61"
        "78223a332c22696e6974696174696e675f6167656e745f6163636573735f636f6e74"
        "726f6c5f7075626c69635f6b6579223a2241414543417751464267634943516f4c44"
        "41304f4478415245684d554652595847426b6147787764486838227d"
    )
    assert encoded == expected
    assert encode_act_plaintext(value) == expected


def test_act_has_no_outer_or_future_extension_fields() -> None:
    forbidden = {
        "version",
        "token_id",
        "issuer_agent_id",
        "subject_agent_id",
        "task_id",
        "protocol_context_hash",
        "tool",
        "action",
        "parameters",
        "resource",
    }
    assert forbidden.isdisjoint(field.name for field in ACT_PLAINTEXT_SCHEMA)


def test_every_tuple_rejects_all_structural_mutations() -> None:
    document = json.loads(VECTOR_PATH.read_text("utf-8"))
    decoders = {
        "agent_user": decode_agent_user_attestation,
        "otk": decode_otk_attestation,
        "provider": decode_provider_attestation,
        "act": decode_act_plaintext,
    }
    for row in document["vectors"]:
        raw = bytes.fromhex(row["canonical_utf8_hex"])
        root = json.loads(raw)
        assert isinstance(root, dict)
        pairs = list(root.items())
        deleted = pairs[1:]
        added = [*pairs, ("unexpected", 0)]
        swapped = [pairs[1], pairs[0], *pairs[2:]]
        wrong_type = [(pairs[0][0], True), *pairs[1:]]
        duplicate = [pairs[0], pairs[0], *pairs[1:]]
        for changed in (deleted, added, swapped, wrong_type, duplicate):
            payload = (
                "{"
                + ",".join(
                    f"{json.dumps(name)}:{json.dumps(value, separators=(',', ':'))}"
                    for name, value in changed
                )
                + "}"
            ).encode()
            with pytest.raises(CanonicalEncodingError):
                decoders[row["tuple_kind"]](payload)


def test_all_canonical_tuple_vectors_are_consumed() -> None:
    document = json.loads(VECTOR_PATH.read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    assert document["format_version"] == 1
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {
            "name",
            "tuple_kind",
            "canonical_utf8_hex",
            "decoded_public_values",
        }
        kind = row["tuple_kind"]
        assert row["name"] == kind and kind not in seen
        seen.add(kind)
        raw = bytes.fromhex(row["canonical_utf8_hex"])
        values = row["decoded_public_values"]
        endpoint = values.get("endpoint")
        endpoint_value = None if endpoint is None else EndpointValue(**endpoint)
        expected = {
            "agent_user": lambda values=values, endpoint_value=endpoint_value: AgentUserAttestation(
                values["agent_id"],
                endpoint_value,
                _tagged_bytes(values["agent_tls_public_key"]),
                _tagged_bytes(values["agent_access_control_public_key"]),
                _tagged_bytes(values["provider_public_key"]),
            ),
            "otk": lambda values=values: OtkAttestation(
                values["agent_id"], _tagged_bytes(values["one_time_public_key"])
            ),
            "provider": lambda values=values, endpoint_value=endpoint_value: ProviderAttestation(
                values["agent_id"],
                _tagged_bytes(values["agent_certificate"]),
                endpoint_value,
                _tagged_bytes(values["agent_access_control_public_key"]),
                _tagged_bytes(values["user_signature"]),
            ),
            "act": lambda values=values: ActPlaintext(
                _tagged_bytes(values["nonce"]),
                values["issued_at"],
                values["expires_at"],
                values["q_max"],
                _tagged_bytes(values["initiating_agent_access_control_public_key"]),
            ),
        }[kind]()
        decode, encode = {
            "agent_user": (decode_agent_user_attestation, encode_agent_user_attestation),
            "otk": (decode_otk_attestation, encode_otk_attestation),
            "provider": (decode_provider_attestation, encode_provider_attestation),
            "act": (decode_act_plaintext, encode_act_plaintext),
        }[kind]
        assert decode(raw) == expected
        assert encode(expected) == raw
    assert seen == {"agent_user", "otk", "provider", "act"}


@pytest.mark.parametrize(
    ("value", "encoder"),
    [
        (
            AgentUserAttestation(
                "agent",
                EndpointValue("device", "192.0.2.1", 443),
                b"opaque",
                b"short",
                bytes(32),
            ),
            encode_agent_user_attestation,
        ),
        (OtkAttestation("agent", b"short"), encode_otk_attestation),
        (
            ProviderAttestation(
                "agent",
                b"opaque",
                EndpointValue("device", "192.0.2.1", 443),
                bytes(32),
                b"short",
            ),
            encode_provider_attestation,
        ),
        (ActPlaintext(b"nonce", 1, 2, 3, b"short"), encode_act_plaintext),
    ],
)
def test_raw_public_keys_and_signature_have_exact_lengths(value: object, encoder: object) -> None:
    with pytest.raises(CanonicalEncodingError):
        encoder(value)  # type: ignore[operator]


def test_tls_key_and_certificate_are_nonempty_opaque_bytes() -> None:
    endpoint = EndpointValue("device", "192.0.2.1", 443)
    agent_user = AgentUserAttestation("agent", endpoint, b"not-der", bytes(32), bytes(32))
    provider = ProviderAttestation("agent", b"not-x509", endpoint, bytes(32), bytes(64))
    assert decode_agent_user_attestation(encode_agent_user_attestation(agent_user)) == agent_user
    assert decode_provider_attestation(encode_provider_attestation(provider)) == provider
    with pytest.raises(CanonicalEncodingError):
        encode_agent_user_attestation(
            AgentUserAttestation("agent", endpoint, b"", bytes(32), bytes(32))
        )
    with pytest.raises(CanonicalEncodingError):
        encode_provider_attestation(
            ProviderAttestation("agent", b"", endpoint, bytes(32), bytes(64))
        )


def test_vector_encoding_is_deterministic_in_a_fresh_process() -> None:
    expected = next(
        row["canonical_utf8_hex"]
        for row in json.loads(VECTOR_PATH.read_text("utf-8"))["vectors"]
        if row["tuple_kind"] == "act"
    )
    script = (
        "from saga.crypto.canonical import ActPlaintext, encode_act_plaintext;"
        "print(encode_act_plaintext(ActPlaintext(bytes(range(16)),1,2,3,"
        "bytes(range(32)))).hex())"
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == expected
