from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

import jwt
from jwt import InvalidTokenError, PyJWKClient, PyJWKClientError
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from shieldchain.core.config import Settings

MCP_BASE_SCOPE = "shieldchain:mcp"
MCP_TOOL_SCOPES = {
    "security.events.list": "shieldchain:events:read",
    "security.alerts.list": "shieldchain:alerts:read",
    "security.vulnerabilities.list": "shieldchain:vulnerabilities:read",
    "security.weak_passwords.list": "shieldchain:auth-risk:read",
}


@dataclass(frozen=True, slots=True)
class McpAuthRuntime:
    auth_settings: AuthSettings | None
    token_verifier: Any | None
    testing_tenant_id: UUID
    testing_principal_id: UUID

    def identity(self) -> tuple[UUID, UUID]:
        if self.token_verifier is None:
            return self.testing_tenant_id, self.testing_principal_id
        token = get_access_token()
        if token is None:
            raise PermissionError("authenticated MCP context is unavailable")
        claims = token.claims or {}
        try:
            tenant_id = UUID(str(claims["shieldchain_tenant_id"]))
            principal_id = UUID(str(claims["shieldchain_principal_id"]))
        except (KeyError, TypeError, ValueError) as error:
            raise PermissionError("verified MCP identity mapping is unavailable") from error
        return tenant_id, principal_id

    def authorize(self, tool_name: str) -> tuple[UUID, UUID]:
        identity = self.identity()
        if self.token_verifier is None:
            return identity
        token = get_access_token()
        if token is None:
            raise PermissionError("authenticated MCP context is unavailable")
        required_scope = MCP_TOOL_SCOPES[tool_name]
        if required_scope not in token.scopes:
            raise PermissionError(f"required scope missing: {required_scope}")
        return identity


def build_mcp_auth_runtime(settings: Settings) -> McpAuthRuntime:
    if settings.mcp_auth_mode == "disabled":
        return McpAuthRuntime(
            auth_settings=None,
            token_verifier=None,
            testing_tenant_id=settings.rag_demo_tenant_id,
            testing_principal_id=settings.rag_demo_principal_id,
        )
    verifier = McpJwtTokenVerifier(
        issuer=settings.mcp_auth_issuer,
        audience=settings.mcp_auth_audience,
        resource=settings.mcp_auth_resource,
        algorithm=settings.mcp_auth_algorithm,
        tenant_id=settings.rag_demo_tenant_id,
        subject_principals=settings.mcp_auth_subject_principals,
        max_token_lifetime_seconds=settings.mcp_auth_max_token_lifetime_seconds,
        jwks_url=settings.mcp_auth_jwks_url,
    )
    return McpAuthRuntime(
        auth_settings=AuthSettings(
            issuer_url=settings.mcp_auth_issuer,
            resource_server_url=settings.mcp_auth_resource,
            required_scopes=[MCP_BASE_SCOPE],
        ),
        token_verifier=verifier,
        testing_tenant_id=settings.rag_demo_tenant_id,
        testing_principal_id=settings.rag_demo_principal_id,
    )


class McpJwtTokenVerifier:
    """Validate externally issued JWT access tokens without retaining raw claims."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        resource: str,
        algorithm: Literal["RS256", "ES256"],
        tenant_id: UUID,
        subject_principals: Mapping[str, UUID],
        max_token_lifetime_seconds: int = 900,
        jwks_url: str | None = None,
        jwk_client: Any | None = None,
    ) -> None:
        if jwk_client is None and jwks_url is None:
            raise ValueError("JWKS URL is required")
        self._issuer = issuer
        self._audience = audience
        self._resource = resource
        self._algorithm = algorithm
        self._tenant_id = tenant_id
        self._subject_principals = dict(subject_principals)
        self._max_token_lifetime_seconds = max_token_lifetime_seconds
        self._jwk_client = jwk_client or PyJWKClient(
            jwks_url,
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != self._algorithm:
                return None
            signing_key = await asyncio.to_thread(self._jwk_client.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            subject = claims["sub"]
            if not isinstance(subject, str) or subject not in self._subject_principals:
                return None
            if claims.get("resource") != self._resource:
                return None
            client_id = claims.get("client_id") or claims.get("azp")
            if not isinstance(client_id, str) or not client_id.strip():
                return None
            scope = claims.get("scope", "")
            if not isinstance(scope, str):
                return None
            scopes = list(dict.fromkeys(item for item in scope.split() if item))
            expires_at = claims["exp"]
            issued_at = claims["iat"]
            if (
                not isinstance(expires_at, int)
                or not isinstance(issued_at, int)
                or not 1 <= expires_at - issued_at <= self._max_token_lifetime_seconds
            ):
                return None
        except (InvalidTokenError, PyJWKClientError, KeyError, TypeError, ValueError):
            return None

        return AccessToken(
            token="",
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=self._resource,
            subject=subject,
            claims={
                "iss": self._issuer,
                "shieldchain_tenant_id": str(self._tenant_id),
                "shieldchain_principal_id": str(self._subject_principals[subject]),
            },
        )
