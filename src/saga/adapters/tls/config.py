"""TLS configuration and SSLContext builders for SAGA mTLS."""

from __future__ import annotations

import ssl
from pathlib import Path


def build_provider_ssl_context(
    cert_path: str | Path,
    key_path: str | Path,
    ca_cert_path: str | Path | None = None,
) -> ssl.SSLContext:
    """Build SSLContext for the Provider's server.
    
    The Provider uses server-authenticated TLS. Client authentication (mTLS) 
    is NOT strictly required at the TLS layer because Users authenticate
    themselves via the application protocol (e.g. passwords, signatures).
    
    However, if `ca_cert_path` is provided, it configures the trust store
    but still does not *require* client certs.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Require TLS 1.3 for best security
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Load server certificate and key
    context.load_cert_chain(certfile=fspath(cert_path), keyfile=fspath(key_path))
    
    # Provider does not strictly require mTLS from Users
    context.verify_mode = ssl.CERT_NONE
    
    if ca_cert_path:
        context.load_verify_locations(cafile=fspath(ca_cert_path))
        
    return context


def build_agent_server_ssl_context(
    cert_path: str | Path,
    key_path: str | Path,
    ca_cert_path: str | Path,
) -> ssl.SSLContext:
    """Build SSLContext for an Agent's server (receiving ACTs).
    
    Agents strictly require mTLS. The connecting client MUST present a valid
    certificate signed by the trusted CA.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    context.load_cert_chain(certfile=fspath(cert_path), keyfile=fspath(key_path))
    
    # Require mTLS
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=fspath(ca_cert_path))
    
    return context


def build_agent_client_ssl_context(
    cert_path: str | Path,
    key_path: str | Path,
    ca_cert_path: str | Path,
) -> ssl.SSLContext:
    """Build SSLContext for an Agent acting as a client (initiating)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # We must present our identity
    context.load_cert_chain(certfile=fspath(cert_path), keyfile=fspath(key_path))
    
    # We must verify the peer
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=fspath(ca_cert_path))
    
    # Strict hostname checking is enabled by default in PROTOCOL_TLS_CLIENT
    context.check_hostname = True
    
    return context


def fspath(path: str | Path) -> str:
    return str(path)
