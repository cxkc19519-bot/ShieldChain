import argparse
import uvicorn
from fastapi import FastAPI
from pathlib import Path

from saga.adapters.http.agent import router as agent_router
from saga.adapters.http.errors import register_exception_handlers
from saga.adapters.persistence.memory import InMemorySotkStore, InMemoryTokenStateStore
from saga.protocols.act_establishment import ActEstablishmentService
from saga.protocols.act_use import ActUseService
from saga.ports.clock import Clock
from saga.ports.random import RandomSource
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.users import UserId
from saga.domain.encoding import EndpointValue


class DummyClock(Clock):
    def now_ms(self) -> int:
        return 1735689600000

class DummyRandomSource(RandomSource):
    def get_bytes(self, num_bytes: int) -> bytes:
        return b"\x01" * num_bytes


def main():
    parser = argparse.ArgumentParser(description="Run SAGA Agent Server")
    parser.add_argument("--port", type=int, default=8001, help="Port to run on")
    parser.add_argument("--name", type=str, default="agent-a", help="Agent name (e.g., agent-a or agent-b)")
    parser.add_argument("--owner", type=str, default="alice", help="Owner ID (e.g., alice)")
    parser.add_argument("--pki-dir", type=Path, default=Path("tests/fixtures/pki"), help="PKI directory")
    args = parser.parse_args()

    app = FastAPI(title=f"SAGA Agent ({args.owner}:{args.name})")
    register_exception_handlers(app)
    app.include_router(agent_router)

    clock = DummyClock()
    sotk_store = InMemorySotkStore()
    token_state_store = InMemoryTokenStateStore()

    agent_id = AgentId(owner=UserId(args.owner), name=args.name)
    app.state.local_agent_id = agent_id
    
    dummy_reg = AgentRegistration(
        owner_id=agent_id.owner,
        agent_id=agent_id,
        endpoint=EndpointValue(device="http", ip="127.0.0.1", port=args.port),
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
        receiving_agent_id=agent_id,
        receiving_registration=dummy_reg,
        random_source=DummyRandomSource(),
    )

    app.state.act_use_service = ActUseService(
        clock=clock,
        token_state_store=token_state_store,
        receiving_agent_id=agent_id,
    )

    print(f"Starting Agent {args.owner}:{args.name} on https://localhost:{args.port}...")
    
    cert_name = args.name.replace("-", "_")  # agent-a -> agent_a
    
    # In production, Agents MUST strictly enforce client certs
    import ssl
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=args.port,
        ssl_certfile=str(args.pki_dir / f"{cert_name}_fullchain.pem"),
        ssl_keyfile=str(args.pki_dir / f"{cert_name}_key.pem"),
        ssl_ca_certs=str(args.pki_dir / "ca_cert.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


if __name__ == "__main__":
    main()
