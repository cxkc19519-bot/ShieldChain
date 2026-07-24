"""ASGI Middleware and dependencies for extracting mTLS peer identity."""

from __future__ import annotations

import ssl
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from fastapi import Request, HTTPException, status
from saga.domain.agents import AgentId
from saga.domain.users import UserId


def _extract_saga_urn(cert_der: bytes) -> str | None:
    """Parse DER certificate and return the SAGA URN from SANs."""
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in sans.value:
            if isinstance(name, x509.UniformResourceIdentifier):
                if name.value.startswith("urn:saga:"):
                    return name.value
    except x509.ExtensionNotFound:
        pass
    return None


def get_peer_identity(request: Request) -> str:
    """FastAPI Dependency: Extract the SAGA URN from the mTLS client certificate.
    
    This expects the ASGI server (e.g. Uvicorn) to implement the ASGI TLS Extension,
    populating `scope["extensions"]["tls"]["client_cert_cert"]` or similar.
    Alternatively, in some setups it might be passed via a header by a proxy.
    """
    # ASGI TLS Extension spec: scope["extensions"]["tls"]["client_cert"] is the DER-encoded cert
    # or the dict from ssl.SSLSocket.getpeercert() depending on the server.
    extensions = request.scope.get("extensions", {})
    tls_ext = extensions.get("tls")
    
    if not tls_ext:
        # For our test/demo environment, we allow a test header if TLS is not strictly
        # configured at the ASGI level, but in production this must be rejected.
        test_identity = request.headers.get("X-Test-Peer-Identity")
        if test_identity:
            return test_identity
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="mTLS client certificate required but not present in ASGI scope.",
        )
        
    client_cert = tls_ext.get("client_cert")
    if not client_cert:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No client certificate provided in TLS handshake.",
        )
        
    # If the server provides the raw DER bytes:
    if isinstance(client_cert, bytes):
        urn = _extract_saga_urn(client_cert)
        if urn:
            return urn
            
    # If the server provides the parsed dict from ssl.getpeercert()
    if isinstance(client_cert, dict):
        sans = client_cert.get("subjectAltName", [])
        for name_type, value in sans:
            if name_type == "URI" and value.startswith("urn:saga:"):
                return value

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Client certificate does not contain a valid SAGA URN identity.",
    )


def get_agent_identity(request: Request) -> AgentId:
    """Dependency to get an authenticated AgentId."""
    urn = get_peer_identity(request)
    if not urn.startswith("urn:saga:agent:"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Expected Agent identity, got {urn}",
        )
    # Format: urn:saga:agent:{owner_id}:{agent_name}
    parts = urn.split(":")
    if len(parts) != 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Malformed Agent URN format",
        )
    try:
        return AgentId(owner=UserId(parts[3]), name=parts[4])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Invalid Agent ID in URN: {e}",
        )
