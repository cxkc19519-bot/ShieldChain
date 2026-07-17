from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ObjectIdentifier, SignatureAlgorithmOID

import saga.crypto.certificates as certificate_module
from saga.crypto.certificates import (
    CertificateValidationError,
    IdentityKind,
    identity_uri,
    load_der_certificate,
    validate_leaf_certificate,
    validated_leaf_public_key_bytes,
)
from tests.helpers.certificates import LEAF_AFTER, LEAF_BEFORE, build_certificate_fixtures

EXPECTED_NEGATIVE_CASES = frozenset(
    {
        "wrong_anchor",
        "wrong_issuer",
        "bad_signature",
        "wrong_san",
        "multiple_saga_san",
        "dns_san_extra",
        "wrong_spki",
        "expired_leaf",
        "future_leaf",
        "expired_anchor",
        "future_anchor",
        "anchor_missing_bc",
        "anchor_ca_false",
        "anchor_bc_not_critical",
        "anchor_path_length_one",
        "anchor_missing_ku",
        "anchor_ku_not_critical",
        "anchor_bad_key_usage",
        "leaf_missing_bc",
        "leaf_ca_true",
        "leaf_bc_not_critical",
        "leaf_missing_ku",
        "leaf_ku_not_critical",
        "leaf_bad_key_usage",
        "leaf_missing_san",
        "leaf_san_critical",
        "leaf_missing_eku",
        "leaf_eku_critical",
        "leaf_wrong_eku",
        "malformed_leaf_der",
        "malformed_anchor_der",
    }
)


def test_user_provider_and_agent_identity_uris_are_unambiguous() -> None:
    assert identity_uri(IdentityKind.USER, "alice") == "urn:saga:user:alice"
    assert identity_uri(IdentityKind.PROVIDER, "provider-1") == "urn:saga:provider:provider-1"
    assert identity_uri(IdentityKind.AGENT, "alice:worker") == "urn:saga:agent:alice%3Aworker"


def test_valid_agent_certificate_binds_identity_and_key() -> None:
    fixtures = build_certificate_fixtures()
    validate_leaf_certificate(
        leaf_der=fixtures.agent.der,
        trust_anchor_der=fixtures.anchor_der,
        expected_kind=IdentityKind.AGENT,
        expected_identifier="alice:worker",
        expected_public_key_spki_der=fixtures.agent.spki_der,
        now_ms=fixtures.now_ms,
    )


@pytest.mark.parametrize("attribute", ["user", "agent"])
def test_validated_leaf_public_key_returns_exact_raw_ed25519_key(
    attribute: str,
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = getattr(fixtures, attribute)
    expected = (
        x509.load_der_x509_certificate(leaf.der)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )

    actual = validated_leaf_public_key_bytes(
        leaf_der=leaf.der,
        trust_anchor_der=fixtures.anchor_der,
        expected_kind=leaf.kind,
        expected_identifier=leaf.identifier,
        now_ms=fixtures.now_ms,
    )

    assert type(actual) is bytes
    assert len(actual) == 32
    assert actual == expected


@pytest.mark.parametrize(
    "case_name",
    [
        "wrong_anchor",
        "wrong_san",
        "expired_leaf",
        "future_leaf",
        "leaf_wrong_eku",
        "malformed_leaf_der",
        "malformed_anchor_der",
    ],
)
def test_validated_leaf_public_key_rejects_invalid_certificates(case_name: str) -> None:
    fixtures = build_certificate_fixtures()
    case = fixtures.negative[case_name]

    with pytest.raises(CertificateValidationError):
        validated_leaf_public_key_bytes(
            leaf_der=case.leaf_der,
            trust_anchor_der=case.anchor_der,
            expected_kind=case.kind,
            expected_identifier=case.identifier,
            now_ms=case.now_ms,
        )


def test_validated_leaf_public_key_rejects_wrong_kind() -> None:
    fixtures = build_certificate_fixtures()

    with pytest.raises(CertificateValidationError):
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=IdentityKind.USER,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize("attribute", ["user", "provider", "agent"])
def test_all_identity_profiles_validate(attribute: str) -> None:
    fixtures = build_certificate_fixtures()
    leaf = getattr(fixtures, attribute)
    validate_leaf_certificate(
        leaf_der=leaf.der,
        trust_anchor_der=fixtures.anchor_der,
        expected_kind=leaf.kind,
        expected_identifier=leaf.identifier,
        expected_public_key_spki_der=leaf.spki_der,
        now_ms=fixtures.now_ms,
    )


@pytest.mark.parametrize("case_name", sorted(EXPECTED_NEGATIVE_CASES))
def test_every_negative_profile_fails(case_name: str) -> None:
    fixtures = build_certificate_fixtures()
    assert set(fixtures.negative) == EXPECTED_NEGATIVE_CASES
    case = fixtures.negative[case_name]
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=case.leaf_der,
            trust_anchor_der=case.anchor_der,
            expected_kind=case.kind,
            expected_identifier=case.identifier,
            expected_public_key_spki_der=case.expected_spki_der,
            now_ms=case.now_ms,
        )


def test_leaf_validity_is_half_open() -> None:
    fixtures = build_certificate_fixtures()
    leaf = fixtures.agent
    common = {
        "leaf_der": leaf.der,
        "trust_anchor_der": fixtures.anchor_der,
        "expected_kind": leaf.kind,
        "expected_identifier": leaf.identifier,
        "expected_public_key_spki_der": leaf.spki_der,
    }
    validate_leaf_certificate(**common, now_ms=int(LEAF_BEFORE.timestamp() * 1000))
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(**common, now_ms=int(LEAF_AFTER.timestamp() * 1000))


@pytest.mark.parametrize(
    "change",
    [
        {"leaf_der": b"not-der"},
        {"trust_anchor_der": b"not-der"},
        {"expected_kind": object()},
        {"expected_identifier": ""},
        {"expected_identifier": object()},
        {"expected_public_key_spki_der": object()},
        {"expected_public_key_spki_der": b""},
        {"now_ms": True},
        {"now_ms": -1},
        {"now_ms": 1.0},
        {"now_ms": object()},
    ],
)
def test_validation_rejects_malformed_boundary_inputs(change: dict[str, object]) -> None:
    fixtures = build_certificate_fixtures()
    leaf = fixtures.agent
    arguments: dict[str, Any] = {
        "leaf_der": leaf.der,
        "trust_anchor_der": fixtures.anchor_der,
        "expected_kind": leaf.kind,
        "expected_identifier": leaf.identifier,
        "expected_public_key_spki_der": leaf.spki_der,
        "now_ms": fixtures.now_ms,
    }
    arguments.update(change)
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(**arguments)


def test_validation_preserves_identity_before_key_binding_error_precedence() -> None:
    fixtures = build_certificate_fixtures()

    with pytest.raises(CertificateValidationError, match="^certificate identity invalid$"):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=object(),  # type: ignore[arg-type]
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=b"",
            now_ms=fixtures.now_ms,
        )


class CertificateProxy:
    def __init__(self, certificate: x509.Certificate, failure: str) -> None:
        self._certificate = certificate
        self._failure = failure

    def __getattr__(self, name: str) -> Any:
        if self._failure == "extension" and name == "extensions":
            raise ValueError
        if self._failure == "signature-algorithm" and name == "signature_algorithm_oid":
            return SignatureAlgorithmOID.RSA_WITH_SHA256
        if self._failure == "unknown-critical-extension" and name == "extensions":
            return ExtensionsProxy(self._certificate.extensions, unknown_critical=True)
        if self._failure == "unexpected-profile-extension" and name == "extensions":
            return ExtensionsProxy(self._certificate.extensions, unknown_critical=False)
        return getattr(self._certificate, name)

    def verify_directly_issued_by(self, issuer: x509.Certificate) -> None:
        if self._failure == "verification":
            raise ValueError
        actual_issuer = issuer._certificate if isinstance(issuer, CertificateProxy) else issuer
        self._certificate.verify_directly_issued_by(actual_issuer)

    def public_key(self) -> Any:
        if self._failure == "public-key-export":
            raise ValueError
        if self._failure == "public-key-algorithm":
            return PublicKeyProxy(self._certificate.public_key())
        return self._certificate.public_key()


class CountingCertificateProxy:
    def __init__(self, certificate: x509.Certificate) -> None:
        self._certificate = certificate
        self.public_key_calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._certificate, name)

    def verify_directly_issued_by(self, issuer: x509.Certificate) -> None:
        self._certificate.verify_directly_issued_by(issuer)

    def public_key(self) -> Any:
        self.public_key_calls += 1
        return self._certificate.public_key()


class InvalidAlgorithmCertificateProxy:
    def __init__(self, certificate: x509.Certificate, invalid_field: str) -> None:
        self._certificate = certificate
        self._invalid_field = invalid_field
        self.public_key_calls = 0

    def __getattr__(self, name: str) -> Any:
        if self._invalid_field == "version" and name == "version":
            return object()
        if self._invalid_field == "signature-algorithm" and name == "signature_algorithm_oid":
            return SignatureAlgorithmOID.RSA_WITH_SHA256
        return getattr(self._certificate, name)

    def public_key(self) -> Any:
        self.public_key_calls += 1
        raise ValueError("backend detail")


@pytest.mark.parametrize("invalid_target", ["leaf", "anchor"])
@pytest.mark.parametrize("invalid_field", ["version", "signature-algorithm"])
def test_invalid_algorithm_metadata_short_circuits_before_public_key_access(
    monkeypatch: pytest.MonkeyPatch, invalid_target: str, invalid_field: str
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = InvalidAlgorithmCertificateProxy(
        x509.load_der_x509_certificate(fixtures.agent.der),
        invalid_field if invalid_target == "leaf" else "none",
    )
    anchor = InvalidAlgorithmCertificateProxy(
        x509.load_der_x509_certificate(fixtures.anchor_der),
        invalid_field if invalid_target == "anchor" else "none",
    )
    values = iter([leaf, anchor])
    monkeypatch.setattr(certificate_module, "load_der_certificate", lambda _: next(values))

    with pytest.raises(CertificateValidationError, match="^certificate algorithm invalid$"):
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )

    assert leaf.public_key_calls == 0
    assert anchor.public_key_calls == 0


@pytest.mark.parametrize("api", ["validate", "extract"])
def test_public_validation_reads_leaf_public_key_exactly_once(
    monkeypatch: pytest.MonkeyPatch, api: str
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = CountingCertificateProxy(x509.load_der_x509_certificate(fixtures.agent.der))
    anchor = x509.load_der_x509_certificate(fixtures.anchor_der)
    values = iter([leaf, anchor])
    monkeypatch.setattr(certificate_module, "load_der_certificate", lambda _: next(values))

    if api == "validate":
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der,
            now_ms=fixtures.now_ms,
        )
    else:
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )

    assert leaf.public_key_calls == 1


class ExtensionsProxy:
    def __init__(self, extensions: x509.Extensions, *, unknown_critical: bool) -> None:
        self._extensions = extensions
        self._unknown_critical = unknown_critical

    def __iter__(self) -> Any:
        yield from self._extensions
        if self._unknown_critical:
            oid = ObjectIdentifier("1.3.6.1.4.1.55555.1")
            yield x509.Extension(oid, True, x509.UnrecognizedExtension(oid, b"x"))
        else:
            yield x509.Extension(
                x509.ExtensionOID.EXTENDED_KEY_USAGE,
                False,
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            )

    def get_extension_for_class(self, extension_type: type[Any]) -> Any:
        return self._extensions.get_extension_for_class(extension_type)


class PublicKeyProxy:
    def __init__(self, public_key: Any) -> None:
        self._public_key = public_key

    def public_bytes(self, encoding: Any, format: Any) -> bytes:
        return self._public_key.public_bytes(encoding, format)


class ExtractionPublicKeyProxy:
    def __init__(self, result: Any) -> None:
        self._result = result

    def public_bytes(self, encoding: Any, format: Any) -> Any:
        if isinstance(self._result, BaseException):
            raise self._result
        return self._result


class BytesSubclass(bytes):
    pass


@pytest.mark.parametrize(
    "result",
    [object(), bytearray(32), b"x" * 31, b"x" * 33, BytesSubclass(b"x" * 32)],
)
def test_validated_leaf_public_key_rejects_malformed_backend_result(
    monkeypatch: pytest.MonkeyPatch, result: object
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    monkeypatch.setattr(
        certificate_module,
        "_validated_leaf_certificate",
        lambda **_: (leaf, ExtractionPublicKeyProxy(result)),
    )

    with pytest.raises(CertificateValidationError, match="^certificate validation failed$"):
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize(
    "error",
    [OSError("backend detail"), TypeError("backend detail"), ValueError("backend detail")],
)
def test_validated_leaf_public_key_normalizes_extraction_failures(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    monkeypatch.setattr(
        certificate_module,
        "_validated_leaf_certificate",
        lambda **_: (leaf, ExtractionPublicKeyProxy(error)),
    )

    with pytest.raises(
        CertificateValidationError, match="^certificate validation failed$"
    ) as caught:
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is error


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_validated_leaf_public_key_system_exceptions_propagate_from_extraction(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    monkeypatch.setattr(
        certificate_module,
        "_validated_leaf_certificate",
        lambda **_: (leaf, ExtractionPublicKeyProxy(error)),
    )

    with pytest.raises(type(error)):
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize("failure", ["verification", "extension", "public-key-export"])
def test_validation_library_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    anchor = x509.load_der_x509_certificate(fixtures.anchor_der)
    values = iter([CertificateProxy(leaf, failure), CertificateProxy(anchor, failure)])
    monkeypatch.setattr(certificate_module, "load_der_certificate", lambda _: next(values))
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize(
    "failure",
    [
        "signature-algorithm",
        "public-key-algorithm",
        "unknown-critical-extension",
        "unexpected-profile-extension",
    ],
)
def test_closed_profile_rejects_unapproved_algorithms_and_extensions(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    anchor = x509.load_der_x509_certificate(fixtures.anchor_der)
    values = iter([CertificateProxy(leaf, failure), CertificateProxy(anchor, failure)])
    monkeypatch.setattr(certificate_module, "load_der_certificate", lambda _: next(values))
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize(
    "failure",
    [
        "verification",
        "extension",
        "public-key-export",
        "public-key-algorithm",
        "unknown-critical-extension",
        "unexpected-profile-extension",
    ],
)
def test_validated_leaf_public_key_normalizes_backend_and_profile_failures(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    anchor = x509.load_der_x509_certificate(fixtures.anchor_der)
    values = iter([CertificateProxy(leaf, failure), CertificateProxy(anchor, failure)])
    monkeypatch.setattr(certificate_module, "load_der_certificate", lambda _: next(values))

    with pytest.raises(CertificateValidationError):
        validated_leaf_public_key_bytes(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            now_ms=fixtures.now_ms,
        )


def test_time_conversion_failure_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = build_certificate_fixtures()

    class FakeDateTime:
        @staticmethod
        def fromtimestamp(*_: object) -> None:
            raise OSError

    monkeypatch.setattr(certificate_module, "datetime", FakeDateTime)
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der,
            now_ms=fixtures.now_ms,
        )


def test_compare_failure_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = build_certificate_fixtures()
    monkeypatch.setattr(
        certificate_module.hmac,
        "compare_digest",
        lambda *_: (_ for _ in ()).throw(ValueError()),
    )
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_validation_system_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    monkeypatch.setattr(
        certificate_module, "load_der_certificate", lambda _: (_ for _ in ()).throw(error)
    )
    with pytest.raises(type(error)):
        validate_leaf_certificate(
            leaf_der=b"x",
            trust_anchor_der=b"y",
            expected_kind=IdentityKind.AGENT,
            expected_identifier="alice:worker",
            expected_public_key_spki_der=b"z",
            now_ms=1,
        )


@pytest.mark.parametrize("data", [object(), "der", b""])
def test_load_der_rejects_bad_input(data: object) -> None:
    with pytest.raises(CertificateValidationError):
        load_der_certificate(data)


@pytest.mark.parametrize(
    "error",
    [OSError(), OverflowError(), TypeError(), UnsupportedAlgorithm("unsupported"), ValueError()],
)
def test_der_library_errors_are_normalized(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def raise_error(_: bytes) -> x509.Certificate:
        raise error

    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_error)
    with pytest.raises(CertificateValidationError):
        load_der_certificate(b"not-empty")


@pytest.mark.parametrize(
    "error",
    [
        x509.DuplicateExtension("duplicate extension", ObjectIdentifier("1.2.3")),
        x509.InvalidVersion("invalid version", 4),
    ],
)
def test_der_x509_profile_errors_are_normalized(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def raise_error(_: bytes) -> x509.Certificate:
        raise error

    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_error)
    with pytest.raises(CertificateValidationError):
        load_der_certificate(b"not-empty")


@pytest.mark.parametrize(
    ("boundary", "error"),
    [
        (
            "extension",
            x509.DuplicateExtension("duplicate extension", ObjectIdentifier("1.2.3")),
        ),
        ("general-name", x509.UnsupportedGeneralNameType("unsupported general name")),
    ],
)
def test_validation_x509_profile_errors_are_normalized(
    monkeypatch: pytest.MonkeyPatch, boundary: str, error: Exception
) -> None:
    fixtures = build_certificate_fixtures()

    if boundary == "extension":
        monkeypatch.setattr(
            certificate_module,
            "_validate_extension_profile",
            lambda *_: (_ for _ in ()).throw(error),
        )
    else:
        monkeypatch.setattr(
            x509.SubjectAlternativeName,
            "get_values_for_type",
            lambda *_: (_ for _ in ()).throw(error),
        )

    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der,
            trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind,
            expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der,
            now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_der_system_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    def raise_error(_: bytes) -> x509.Certificate:
        raise error

    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_error)
    with pytest.raises(type(error)):
        load_der_certificate(b"not-empty")


@pytest.mark.parametrize("identifier", ["", "a\x00", "a\x7f", "a\u0085", "\ud800"])
def test_identity_input_failures(identifier: str) -> None:
    with pytest.raises(CertificateValidationError):
        identity_uri(IdentityKind.AGENT, identifier)
