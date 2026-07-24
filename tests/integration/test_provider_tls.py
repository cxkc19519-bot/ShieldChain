"""Integration tests for Provider API and TLS enforcement."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI

from saga.adapters.http.provider import router as provider_router
from saga.adapters.http.errors import register_exception_handlers
from saga.adapters.tls.config import build_provider_ssl_context, build_agent_client_ssl_context
from saga.domain.agents import AgentId
from saga.domain.users import UserId
from saga.ports.clock import Clock
from saga.ports.identity import IdentityVerifier
from saga.ports.random import RandomSource
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.protocols.user_registration import UserRegistrationService
from saga.protocols.contact_resolution import ContactResolutionService


@pytest.fixture(scope="session")
def pki_dir() -> Path:
    p = Path("tests/fixtures/pki")
    if not p.exists():
        pytest.skip("Test PKI not generated. Run scripts/create_test_ca.py first.")
    return p


class DummyClock(Clock):
    def now_ms(self) -> int:
        return 1735689600000

class DummyRandomSource(RandomSource):
    def get_bytes(self, num_bytes: int) -> bytes:
        return b"\x01" * num_bytes

class DummyIdentityVerifier(IdentityVerifier):
    def verify_identity(self, user_id: UserId, password: str) -> None:
        pass


@pytest.fixture
def provider_app(pki_dir: Path) -> FastAPI:
    app = FastAPI(title="SAGA Provider")
    register_exception_handlers(app)
    app.include_router(provider_router)
    
    clock = DummyClock()
    registry = InMemoryUserRegistry()
    agent_registry = InMemoryAgentRegistry()
    
    with open(pki_dir / "ca_cert.pem", "rb") as f:
        trust_anchor_der = f.read()  # Need DER for protocols but for now this is fake
    
    app.state.user_registration_service = UserRegistrationService(
        identity_verifier=DummyIdentityVerifier(),
        user_registry=registry,
        clock=clock,
        random_source=DummyRandomSource(),
        trust_anchor_der=b"dummy",
    )
    
    app.state.contact_resolution_service = ContactResolutionService(
        contact_state_store=agent_registry,
        user_registry=registry,
    )
    
    return app


@pytest_asyncio.fixture
async def provider_server(provider_app: FastAPI, pki_dir: Path, unused_tcp_port: int):
    # This runs the provider using Uvicorn with real TLS in the background
    config = uvicorn.Config(
        app=provider_app,
        host="127.0.0.1",
        port=unused_tcp_port,
        ssl_certfile=str(pki_dir / "provider_fullchain.pem"),
        ssl_keyfile=str(pki_dir / "provider_key.pem"),
        ssl_ca_certs=str(pki_dir / "ca_cert.pem"),
        # To enforce mTLS, normally we'd set ssl_cert_reqs=ssl.CERT_REQUIRED
        # But for the Provider, we don't require client certs.
        ssl_cert_reqs=0, # ssl.CERT_NONE
        log_level="critical",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    
    # Wait for server to start
    await asyncio.sleep(0.5)
    
    yield f"https://localhost:{unused_tcp_port}"
    
    server.should_exit = True
    await task


@pytest.mark.asyncio
async def test_provider_server_auth(provider_server: str, pki_dir: Path) -> None:
    # Client MUST trust the CA to connect
    ca_cert = pki_dir / "ca_cert.pem"
    
    # Context that verifies the server
    import ssl
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    
    async with httpx.AsyncClient(verify=ctx) as client:
        # A simple request should succeed (even if 404, TLS handshake passed)
        response = await client.get(provider_server + "/docs")
        assert response.status_code == 200

    # Context that DOES NOT trust the CA should fail
    bad_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    with pytest.raises(httpx.ConnectError):
        async with httpx.AsyncClient(verify=bad_ctx) as client:
            await client.get(provider_server + "/docs")
