import hmac
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeVar
from urllib.parse import quote

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, SignatureAlgorithmOID

from saga.domain.encoding import require_unix_ms


class CertificateValidationError(ValueError):
    """A certificate fails the closed SAGA validation profile."""


class IdentityKind(StrEnum):
    USER = "user"
    PROVIDER = "provider"
    AGENT = "agent"


def identity_uri(kind: IdentityKind, identifier: str) -> str:
    """Return urn:saga:<kind>:<percent-encoded UTF-8 identifier>."""
    try:
        if (
            not isinstance(kind, IdentityKind)
            or not isinstance(identifier, str)
            or not identifier
            or any(unicodedata.category(character) == "Cc" for character in identifier)
        ):
            raise CertificateValidationError("certificate identity invalid")
        return f"urn:saga:{kind.value}:{quote(identifier, safe='-._~')}"
    except CertificateValidationError:
        raise
    except (TypeError, ValueError):
        raise CertificateValidationError("certificate identity invalid") from None


_EXPECTED_EKU = {
    IdentityKind.USER: frozenset({ExtendedKeyUsageOID.CLIENT_AUTH}),
    IdentityKind.PROVIDER: frozenset({ExtendedKeyUsageOID.SERVER_AUTH}),
    IdentityKind.AGENT: frozenset(
        {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}
    ),
}

T = TypeVar("T", bound=x509.ExtensionType)


def _extension(
    certificate: x509.Certificate, extension_type: type[T], *, critical: bool
) -> x509.Extension[T]:
    extension = certificate.extensions.get_extension_for_class(extension_type)
    if extension.critical is not critical:
        raise CertificateValidationError("certificate extension criticality invalid")
    return extension


def _key_usage_values(usage: x509.KeyUsage) -> tuple[bool, ...]:
    encipher_only = usage.encipher_only if usage.key_agreement else False
    decipher_only = usage.decipher_only if usage.key_agreement else False
    return (
        usage.digital_signature,
        usage.content_commitment,
        usage.key_encipherment,
        usage.data_encipherment,
        usage.key_agreement,
        usage.key_cert_sign,
        usage.crl_sign,
        encipher_only,
        decipher_only,
    )


def _anchor_key_usage_is_exact(usage: x509.KeyUsage) -> bool:
    return _key_usage_values(usage) == (
        False,
        False,
        False,
        False,
        False,
        True,
        True,
        False,
        False,
    )


def _leaf_key_usage_is_exact(usage: x509.KeyUsage) -> bool:
    return _key_usage_values(usage) == (
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
    )


def load_der_certificate(data: bytes) -> x509.Certificate:
    try:
        if type(data) is not bytes or not data:
            raise CertificateValidationError("certificate encoding invalid")
        return x509.load_der_x509_certificate(data)
    except CertificateValidationError:
        raise
    except (
        OSError,
        OverflowError,
        TypeError,
        UnsupportedAlgorithm,
        ValueError,
        x509.DuplicateExtension,
        x509.InvalidVersion,
        x509.UnsupportedGeneralNameType,
    ):
        raise CertificateValidationError("certificate encoding invalid") from None


def _validate_algorithm_profile(leaf: x509.Certificate, anchor: x509.Certificate) -> None:
    if (
        leaf.version is not x509.Version.v3
        or anchor.version is not x509.Version.v3
        or leaf.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
        or anchor.signature_algorithm_oid != SignatureAlgorithmOID.ED25519
        or not isinstance(leaf.public_key(), Ed25519PublicKey)
        or not isinstance(anchor.public_key(), Ed25519PublicKey)
    ):
        raise CertificateValidationError("certificate algorithm invalid")


def _validate_extension_profile(leaf: x509.Certificate, anchor: x509.Certificate) -> None:
    anchor_oids = [extension.oid for extension in anchor.extensions]
    leaf_oids = [extension.oid for extension in leaf.extensions]
    expected_anchor_oids = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}
    expected_leaf_oids = {
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    }
    if (
        len(anchor_oids) != len(expected_anchor_oids)
        or set(anchor_oids) != expected_anchor_oids
        or len(leaf_oids) != len(expected_leaf_oids)
        or set(leaf_oids) != expected_leaf_oids
    ):
        raise CertificateValidationError("certificate extension invalid")


def validate_leaf_certificate(
    *,
    leaf_der: bytes,
    trust_anchor_der: bytes,
    expected_kind: IdentityKind,
    expected_identifier: str,
    expected_public_key_spki_der: bytes,
    now_ms: int,
) -> None:
    try:
        if not isinstance(expected_kind, IdentityKind):
            raise CertificateValidationError("certificate identity invalid")
        if type(expected_public_key_spki_der) is not bytes or not expected_public_key_spki_der:
            raise CertificateValidationError("certificate key binding invalid")
        leaf = load_der_certificate(leaf_der)
        anchor = load_der_certificate(trust_anchor_der)
        now = datetime.fromtimestamp(require_unix_ms(now_ms, "now_ms") / 1000, UTC)
        expected_uri = identity_uri(expected_kind, expected_identifier)
        _validate_algorithm_profile(leaf, anchor)
        _validate_extension_profile(leaf, anchor)
        anchor_bc = _extension(anchor, x509.BasicConstraints, critical=True).value
        leaf_bc = _extension(leaf, x509.BasicConstraints, critical=True).value
        anchor_ku = _extension(anchor, x509.KeyUsage, critical=True).value
        leaf_ku = _extension(leaf, x509.KeyUsage, critical=True).value
        if (
            not anchor_bc.ca
            or anchor_bc.path_length != 0
            or leaf_bc.ca
            or leaf.issuer != anchor.subject
            or anchor.subject != anchor.issuer
        ):
            raise CertificateValidationError("certificate chain invalid")
        anchor.verify_directly_issued_by(anchor)
        leaf.verify_directly_issued_by(anchor)
        if not (
            anchor.not_valid_before_utc <= now < anchor.not_valid_after_utc
            and leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
        ):
            raise CertificateValidationError("certificate validity invalid")
        if not _anchor_key_usage_is_exact(anchor_ku) or not _leaf_key_usage_is_exact(leaf_ku):
            raise CertificateValidationError("certificate usage invalid")
        eku = _extension(leaf, x509.ExtendedKeyUsage, critical=False).value
        if frozenset(eku) != _EXPECTED_EKU[expected_kind]:
            raise CertificateValidationError("certificate usage invalid")
        general_names = _extension(leaf, x509.SubjectAlternativeName, critical=False).value
        uris = general_names.get_values_for_type(x509.UniformResourceIdentifier)
        if len(general_names) != 1 or uris != [expected_uri]:
            raise CertificateValidationError("certificate identity invalid")
        actual_spki = leaf.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        if not hmac.compare_digest(actual_spki, expected_public_key_spki_der):
            raise CertificateValidationError("certificate key binding invalid")
    except CertificateValidationError:
        raise
    except (
        AttributeError,
        InvalidSignature,
        OSError,
        OverflowError,
        TypeError,
        UnsupportedAlgorithm,
        ValueError,
        x509.DuplicateExtension,
        x509.ExtensionNotFound,
        x509.InvalidVersion,
        x509.UnsupportedGeneralNameType,
    ):
        raise CertificateValidationError("certificate validation failed") from None
