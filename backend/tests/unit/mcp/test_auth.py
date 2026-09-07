from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shieldchain.mcp_auth import McpJwtTokenVerifier

ISSUER = "https://identity.example.test"
AUDIENCE = "shieldchain-mcp"
RESOURCE = "https://shieldchain.example.test/mcp"
TENANT = UUID("00000000-0000-4000-8000-000000000001")
PRINCIPAL = UUID("00000000-0000-4000-8000-000000000010")


@pytest.fixture(scope="module")
def signing_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _token(private_key, **updates) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "security-operator",
        "client_id": "codex-mcp-client",
        "scope": "shieldchain:alerts:read",
        "resource": RESOURCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(updates)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def _verifier(public_key) -> McpJwtTokenVerifier:
    jwk_client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=public_key)
    )
    return McpJwtTokenVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        resource=RESOURCE,
        algorithm="RS256",
        tenant_id=TENANT,
        subject_principals={"security-operator": PRINCIPAL},
        jwk_client=jwk_client,
    )


def test_jwt_verifier_returns_only_bounded_access_context(signing_keys) -> None:
    private_key, public_key = signing_keys

    access = asyncio.run(_verifier(public_key).verify_token(_token(private_key)))

    assert access is not None
    assert access.token == ""
    assert access.client_id == "codex-mcp-client"
    assert access.subject == "security-operator"
    assert access.scopes == ["shieldchain:alerts:read"]
    assert access.resource == RESOURCE
    assert access.claims == {
        "iss": ISSUER,
        "shieldchain_tenant_id": str(TENANT),
        "shieldchain_principal_id": str(PRINCIPAL),
    }


@pytest.mark.parametrize(
    "updates",
    [
        {"iss": "https://wrong.example.test"},
        {"aud": "wrong-audience"},
        {"resource": "https://wrong.example.test/mcp"},
        {"sub": "unknown-subject"},
        {"exp": datetime.now(UTC) - timedelta(minutes=1)},
        {"exp": datetime.now(UTC) + timedelta(hours=1)},
        {"client_id": "", "azp": ""},
        {"scope": {"not": "valid"}},
    ],
)
def test_jwt_verifier_rejects_invalid_or_unmapped_tokens(signing_keys, updates) -> None:
    private_key, public_key = signing_keys

    access = asyncio.run(_verifier(public_key).verify_token(_token(private_key, **updates)))

    assert access is None


def test_jwt_verifier_rejects_algorithm_confusion(signing_keys) -> None:
    private_key, public_key = signing_keys
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "security-operator",
            "client_id": "client",
            "scope": "shieldchain:alerts:read",
            "resource": RESOURCE,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        private_key,
        algorithm="PS256",
        headers={"kid": "test-key"},
    )

    assert asyncio.run(_verifier(public_key).verify_token(token)) is None
