"""Public synthetic test seeds used only to build in-memory certificate fixtures."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from saga.crypto.certificates import IdentityKind, identity_uri

ROOT_BEFORE = datetime(2025, 1, 1, tzinfo=UTC)
ROOT_AFTER = datetime(2035, 1, 1, tzinfo=UTC)
LEAF_BEFORE = datetime(2026, 1, 1, tzinfo=UTC)
LEAF_AFTER = datetime(2027, 1, 1, tzinfo=UTC)
NOW_MS = 1_767_225_600_000


@dataclass(frozen=True, slots=True)
class LeafFixture:
    der: bytes
    spki_der: bytes
    kind: IdentityKind
    identifier: str


@dataclass(frozen=True, slots=True)
class ValidationCase:
    leaf_der: bytes
    anchor_der: bytes
    kind: IdentityKind
    identifier: str
    expected_spki_der: bytes
    now_ms: int


@dataclass(frozen=True, slots=True)
class CertificateFixtureSet:
    anchor_der: bytes
    now_ms: int
    user: LeafFixture
    provider: LeafFixture
    agent: LeafFixture
    negative: Mapping[str, ValidationCase]


def _private(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def _anchor_usage() -> x509.KeyUsage:
    return x509.KeyUsage(False, False, False, False, False, True, True, False, False)


def _leaf_usage() -> x509.KeyUsage:
    return x509.KeyUsage(True, False, False, False, False, False, False, False, False)


def _build_anchor(
    key: Ed25519PrivateKey,
    *,
    include_bc: bool = True,
    ca: bool = True,
    path_length: int | None = 0,
    bc_critical: bool = True,
    include_ku: bool = True,
    key_usage: x509.KeyUsage | None = None,
    ku_critical: bool = True,
    not_before: datetime = ROOT_BEFORE,
    not_after: datetime = ROOT_AFTER,
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAGA Phase 1 Test Root")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if include_bc:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=bc_critical
        )
    if include_ku:
        builder = builder.add_extension(key_usage or _anchor_usage(), critical=ku_critical)
    return builder.sign(key, algorithm=None)


def _eku(kind: IdentityKind) -> x509.ExtendedKeyUsage:
    values = {
        IdentityKind.USER: [ExtendedKeyUsageOID.CLIENT_AUTH],
        IdentityKind.PROVIDER: [ExtendedKeyUsageOID.SERVER_AUTH],
        IdentityKind.AGENT: [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
    }
    return x509.ExtendedKeyUsage(values[kind])


def _build_leaf(
    anchor: x509.Certificate,
    anchor_key: Ed25519PrivateKey,
    *,
    seed_byte: int,
    serial: int,
    kind: IdentityKind,
    identifier: str,
    issuer_name: x509.Name | None = None,
    signer_key: Ed25519PrivateKey | None = None,
    not_before: datetime = LEAF_BEFORE,
    not_after: datetime = LEAF_AFTER,
    include_bc: bool = True,
    ca: bool = False,
    bc_critical: bool = True,
    include_ku: bool = True,
    key_usage: x509.KeyUsage | None = None,
    ku_critical: bool = True,
    include_san: bool = True,
    san_names: list[x509.GeneralName] | None = None,
    san_critical: bool = False,
    include_eku: bool = True,
    eku: x509.ExtendedKeyUsage | None = None,
    eku_critical: bool = False,
) -> LeafFixture:
    key = _private(seed_byte)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identifier)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or anchor.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if include_bc:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=bc_critical
        )
    if include_ku:
        builder = builder.add_extension(key_usage or _leaf_usage(), critical=ku_critical)
    if include_san:
        names = san_names or [x509.UniformResourceIdentifier(identity_uri(kind, identifier))]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=san_critical)
    if include_eku:
        builder = builder.add_extension(eku or _eku(kind), critical=eku_critical)
    certificate = builder.sign(signer_key or anchor_key, algorithm=None)
    return LeafFixture(
        certificate.public_bytes(Encoding.DER),
        key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
        kind,
        identifier,
    )


def build_certificate_fixtures() -> CertificateFixtureSet:
    root_key = _private(1)
    anchor = _build_anchor(root_key)
    anchor_der = anchor.public_bytes(Encoding.DER)
    user = _build_leaf(
        anchor, root_key, seed_byte=2, serial=2, kind=IdentityKind.USER, identifier="alice"
    )
    provider = _build_leaf(
        anchor,
        root_key,
        seed_byte=3,
        serial=3,
        kind=IdentityKind.PROVIDER,
        identifier="provider-1",
    )
    agent = _build_leaf(
        anchor,
        root_key,
        seed_byte=4,
        serial=4,
        kind=IdentityKind.AGENT,
        identifier="alice:worker",
    )
    return CertificateFixtureSet(
        anchor_der,
        NOW_MS,
        user,
        provider,
        agent,
        MappingProxyType(_build_negative_cases(anchor, root_key, agent, anchor_der)),
    )


def _case(
    leaf: LeafFixture,
    anchor_der: bytes,
    *,
    identifier: str | None = None,
    spki: bytes | None = None,
    now_ms: int = NOW_MS,
) -> ValidationCase:
    return ValidationCase(
        leaf.der,
        anchor_der,
        leaf.kind,
        identifier or leaf.identifier,
        spki or leaf.spki_der,
        now_ms,
    )


def _build_negative_cases(
    anchor: x509.Certificate,
    root_key: Ed25519PrivateKey,
    agent: LeafFixture,
    anchor_der: bytes,
) -> dict[str, ValidationCase]:
    def leaf(serial: int, **kwargs: Any) -> LeafFixture:
        return _build_leaf(
            anchor,
            root_key,
            seed_byte=20 + serial,
            serial=100 + serial,
            kind=IdentityKind.AGENT,
            identifier="alice:worker",
            **kwargs,
        )

    alternate_key = _private(9)
    alternate_anchor = _build_anchor(alternate_key)
    alternate_der = alternate_anchor.public_bytes(Encoding.DER)
    bad_anchor_usage = x509.KeyUsage(True, False, False, False, False, True, True, False, False)
    bad_leaf_usage = x509.KeyUsage(True, False, True, False, False, False, False, False, False)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong issuer")])
    cases = {
        "wrong_anchor": _case(agent, alternate_der),
        "wrong_issuer": _case(leaf(1, issuer_name=other_name), anchor_der),
        "bad_signature": _case(leaf(2, signer_key=alternate_key), anchor_der),
        "wrong_san": _case(agent, anchor_der, identifier="alice:other"),
        "multiple_saga_san": _case(
            leaf(
                3,
                san_names=[
                    x509.UniformResourceIdentifier("urn:saga:agent:alice%3Aworker"),
                    x509.UniformResourceIdentifier("urn:saga:agent:alice%3Aother"),
                ],
            ),
            anchor_der,
        ),
        "dns_san_extra": _case(
            leaf(
                4,
                san_names=[
                    x509.UniformResourceIdentifier("urn:saga:agent:alice%3Aworker"),
                    x509.DNSName("example.test"),
                ],
            ),
            anchor_der,
        ),
        "wrong_spki": _case(agent, anchor_der, spki=b"\x30\x00"),
        "expired_leaf": _case(agent, anchor_der, now_ms=1_798_761_600_000),
        "future_leaf": _case(agent, anchor_der, now_ms=1_735_689_600_000),
        "anchor_missing_bc": _case(
            agent, _build_anchor(root_key, include_bc=False).public_bytes(Encoding.DER)
        ),
        "anchor_ca_false": _case(
            agent,
            _build_anchor(root_key, ca=False, path_length=None).public_bytes(Encoding.DER),
        ),
        "anchor_bc_not_critical": _case(
            agent, _build_anchor(root_key, bc_critical=False).public_bytes(Encoding.DER)
        ),
        "anchor_path_length_one": _case(
            agent, _build_anchor(root_key, path_length=1).public_bytes(Encoding.DER)
        ),
        "anchor_missing_ku": _case(
            agent, _build_anchor(root_key, include_ku=False).public_bytes(Encoding.DER)
        ),
        "anchor_ku_not_critical": _case(
            agent, _build_anchor(root_key, ku_critical=False).public_bytes(Encoding.DER)
        ),
        "anchor_bad_key_usage": _case(
            agent,
            _build_anchor(root_key, key_usage=bad_anchor_usage).public_bytes(Encoding.DER),
        ),
        "leaf_missing_bc": _case(leaf(5, include_bc=False), anchor_der),
        "leaf_ca_true": _case(leaf(6, ca=True), anchor_der),
        "leaf_bc_not_critical": _case(leaf(12, bc_critical=False), anchor_der),
        "leaf_missing_ku": _case(leaf(7, include_ku=False), anchor_der),
        "leaf_ku_not_critical": _case(leaf(13, ku_critical=False), anchor_der),
        "leaf_bad_key_usage": _case(leaf(8, key_usage=bad_leaf_usage), anchor_der),
        "leaf_missing_san": _case(leaf(9, include_san=False), anchor_der),
        "leaf_san_critical": _case(leaf(14, san_critical=True), anchor_der),
        "leaf_missing_eku": _case(leaf(10, include_eku=False), anchor_der),
        "leaf_eku_critical": _case(leaf(15, eku_critical=True), anchor_der),
        "leaf_wrong_eku": _case(
            leaf(11, eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])),
            anchor_der,
        ),
        "malformed_leaf_der": ValidationCase(
            b"not-der", anchor_der, agent.kind, agent.identifier, agent.spki_der, NOW_MS
        ),
        "malformed_anchor_der": ValidationCase(
            agent.der, b"not-der", agent.kind, agent.identifier, agent.spki_der, NOW_MS
        ),
    }
    cases["expired_anchor"] = _case(
        agent, _build_anchor(root_key, not_after=LEAF_BEFORE).public_bytes(Encoding.DER)
    )
    cases["future_anchor"] = _case(
        agent, _build_anchor(root_key, not_before=LEAF_AFTER).public_bytes(Encoding.DER)
    )
    return cases
