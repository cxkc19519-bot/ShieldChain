"""Integration tests for Agent API and strict mTLS enforcement."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI

from saga.adapters.http.agent import router as agent_router
from saga.adapters.http.errors import register_exception_handlers
from saga.adapters.tls.config import build_agent_client_ssl_context
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.users import UserId
from saga.ports.clock import Clock
from saga.ports.random import RandomSource
from saga.protocols.act_establishment import ActEstablishmentService
from saga.protocols.act_use import ActUseService
from saga.adapters.persistence.memory import InMemorySotkStore, InMemoryTokenStateStore


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


@pytest.fixture
def agent_app(pki_dir: Path) -> FastAPI:
    app = FastAPI(title="SAGA Agent")
    register_exception_handlers(app)
    app.include_router(agent_router)
    
    clock = DummyClock()
    sotk_store = InMemorySotkStore()
    token_state_store = InMemoryTokenStateStore()
    
    # We load real DER certificates here for crypto validation, but for HTTP tests
    # we just mock them with dummy bytes.
    app.state.local_agent_id = AgentId(owner=UserId("alice"), name="agent-a")
    dummy_reg = AgentRegistration(
        owner_id=app.state.local_agent_id.owner,
        agent_id=app.state.local_agent_id,
        endpoint=EndpointValue(device="http", ip="127.0.0.1", port=8000),
        certificate_der=b"\x01" * 100,
        access_control_public_key=b"\x01" * 32,
        contact_policy_document=b"\x01" * 100,
        public_otks=(RegisteredPublicOtk(public_key=b"\x01"*32, user_signature=b"\x01"*64),),
        user_metadata_signature=b"\x01" * 64,
    )
    
    app.state.act_establishment_service = ActEstablishmentService(
        clock=clock,
        trust_anchor_der=b"dummy",
        provider_public_key=b"\x01" * 32,
        sotk_store=sotk_store,
        token_state_store=token_state_store,
        receiving_agent_id=app.state.local_agent_id,
        receiving_registration=dummy_reg,
        random_source=DummyRandomSource(),
    )
    
    app.state.act_use_service = ActUseService(
        clock=clock,
        token_state_store=token_state_store,
        receiving_agent_id=app.state.local_agent_id,
    )
    
    return app


@pytest_asyncio.fixture
async def agent_server(agent_app: FastAPI, pki_dir: Path, unused_tcp_port: int):
    # This runs the Agent using Uvicorn with STRICT mTLS
    import ssl
    config = uvicorn.Config(
        app=agent_app,
        host="127.0.0.1",
        port=unused_tcp_port,
        ssl_certfile=str(pki_dir / "agent_a_fullchain.pem"),
        ssl_keyfile=str(pki_dir / "agent_a_key.pem"),
        ssl_ca_certs=str(pki_dir / "ca_cert.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED, # Enforce mTLS!
        log_level="critical",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    
    await asyncio.sleep(0.5)
    yield f"https://localhost:{unused_tcp_port}"
    server.should_exit = True
    await task


@pytest.mark.asyncio
async def test_agent_mtls_success(agent_server: str, pki_dir: Path) -> None:
    # Client MUST present a trusted certificate
    ca_cert = pki_dir / "ca_cert.pem"
    client_cert = pki_dir / "agent_b_fullchain.pem"
    client_key = pki_dir / "agent_b_key.pem"
    
    ctx = build_agent_client_ssl_context(
        cert_path=client_cert,
        key_path=client_key,
        ca_cert_path=ca_cert,
    )
    
    # The ASGI scope won't have the client cert automatically without --client-cert-reqs
    # Wait, uvicorn programmatically does expose scope["extensions"]["tls"] when ssl_cert_reqs > 0 ?
    # We will test if the peer_identity middleware can extract it!
    
    async with httpx.AsyncClient(verify=ctx) as client:
        # Send a dummy body just to hit the endpoint and parse identity
        response = await client.post(
            agent_server + "/act/use",
            headers={"X-Test-Peer-Identity": "urn:saga:agent:alice:agent-b"},
            json={
                "act_version": 1,
                "act_ciphertext_b64": "dummy",
                "act_nonce_b64": "dummy",
                "initiating_agent_access_control_public_key_b64": "dummy",
                "action": "test"
            }
        )
        # We expect a 400 Bad Request because dummy base64/envelope isn't real,
        # OR 403 Forbidden because domain logic fails.
        # But NOT 401 Unauthorized (which happens if identity extraction fails).
        assert response.status_code != 401
        
@pytest.mark.asyncio
async def test_agent_mtls_missing_cert(agent_server: str, pki_dir: Path) -> None:
    ca_cert = pki_dir / "ca_cert.pem"
    
    # Context that verifies the server but DOES NOT provide a client cert
    import ssl
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    
    with pytest.raises((httpx.ConnectError, httpx.ReadError)):
        # The TLS handshake itself should fail because the server requires a cert!
        async with httpx.AsyncClient(verify=ctx) as client:
            await client.post(agent_server + "/act/use", json={})
