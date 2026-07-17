import saga.crypto as crypto
import saga.domain as domain
from saga.crypto import passwords


def test_crypto_public_api_is_exact() -> None:
    expected = (
        "ActEnvelope",
        "ActPlaintext",
        "AeadError",
        "AgentUserAttestation",
        "CanonicalEncodingError",
        "CertificateValidationError",
        "IdentityKind",
        "KeyAgreementError",
        "KeyDerivationError",
        "OtkAttestation",
        "ProviderAttestation",
        "SignatureError",
        "decode_act_plaintext",
        "decode_agent_user_attestation",
        "decode_otk_attestation",
        "decode_provider_attestation",
        "decrypt_act",
        "derive_sdhk",
        "derive_shared_secret",
        "ed25519_public_key",
        "ed25519_public_key_bytes",
        "ed25519_public_key_from_bytes",
        "encode_act_plaintext",
        "encode_agent_user_attestation",
        "encode_otk_attestation",
        "encode_provider_attestation",
        "encrypt_act",
        "generate_ed25519_private_key",
        "generate_x25519_private_key",
        "identity_uri",
        "load_der_certificate",
        "sign",
        "validate_leaf_certificate",
        "validated_leaf_public_key_bytes",
        "verify",
        "x25519_public_key",
        "x25519_public_key_bytes",
        "x25519_public_key_from_bytes",
    )
    assert crypto.__all__ == expected
    assert len(crypto.__all__) == len(set(crypto.__all__))
    assert all(hasattr(crypto, name) for name in expected)
    assert crypto.IdentityKind.PROVIDER.value == "provider"
    assert not hasattr(crypto, "PasswordRecord")
    assert not hasattr(crypto, "hash_password")


def test_password_submodule_api_is_exact() -> None:
    assert passwords.__all__ == (
        "PasswordRecord",
        "PasswordRecordError",
        "hash_password",
        "verify_password",
    )
    assert all(hasattr(passwords, name) for name in passwords.__all__)


def test_domain_public_api_is_exact() -> None:
    expected = (
        "AgentEndpointExists",
        "AgentId",
        "AgentIdentifierExists",
        "AgentOwnerAuthenticationFailed",
        "AgentRegistered",
        "AgentRegistration",
        "AgentRegistrationVerificationFailed",
        "EncodingError",
        "EndpointValue",
        "IdentityVerificationRejected",
        "InvalidRegistrationInput",
        "RegisteredPublicOtk",
        "RegisterAgentCommand",
        "RegisterUserCommand",
        "RegistrationError",
        "RegistrationEvent",
        "RegistrationPersistenceError",
        "UserId",
        "UserRegistered",
        "UserRegistration",
        "UserRegistrationExists",
        "b64url_decode",
        "b64url_encode",
        "require_unix_ms",
    )
    assert domain.__all__ == expected
    assert len(domain.__all__) == len(set(domain.__all__))
    assert all(hasattr(domain, name) for name in expected)
