import argparse
import uvicorn
from fastapi import FastAPI
from pathlib import Path

from saga.adapters.http.provider import router as provider_router
from saga.adapters.http.errors import register_exception_handlers
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.protocols.agent_registration import UserRegistrationService
from saga.protocols.contact_resolution import ContactResolutionService
from saga.ports.identity import IdentityVerifier
from saga.ports.clock import Clock
from saga.ports.random import RandomSource
from saga.domain.users import UserId
from saga.crypto.passwords import hash_password


class DummyClock(Clock):
    def now_ms(self) -> int:
        return 1735689600000

class DummyRandomSource(RandomSource):
    def get_bytes(self, num_bytes: int) -> bytes:
        return b"\x01" * num_bytes

class DummyIdentityVerifier(IdentityVerifier):
    def verify_identity(self, user_id: UserId, password: str) -> None:
        pass


def main():
    parser = argparse.ArgumentParser(description="Run SAGA Provider Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to run on")
    parser.add_argument("--pki-dir", type=Path, default=Path("tests/fixtures/pki"), help="PKI directory")
    args = parser.parse_args()

    app = FastAPI(title="SAGA Provider API")
    register_exception_handlers(app)
    app.include_router(provider_router)

    clock = DummyClock()
    user_registry = InMemoryUserRegistry()
    agent_registry = InMemoryAgentRegistry()
    
    # Pre-register Alice and Bob for demo
    dummy_password = hash_password("password")
    
    # Normally we would use UserRegistration, but this is a simplified demo injection
    # In a real app we'd expose a CLI tool or API for user onboarding.
    
    app.state.user_registration_service = UserRegistrationService(
        identity_verifier=DummyIdentityVerifier(),
        user_registry=user_registry,
        clock=clock,
        random_source=DummyRandomSource(),
        trust_anchor_der=b"dummy",
    )

    app.state.contact_resolution_service = ContactResolutionService(
        contact_state_store=agent_registry,
        user_registry=user_registry,
    )

    print(f"Starting Provider on https://localhost:{args.port}...")
    
    # In production, Provider MUST NOT enforce client certs globally (some endpoints are public)
    import ssl
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=args.port,
        ssl_certfile=str(args.pki_dir / "provider_fullchain.pem"),
        ssl_keyfile=str(args.pki_dir / "provider_key.pem"),
        ssl_ca_certs=str(args.pki_dir / "ca_cert.pem"),
        ssl_cert_reqs=ssl.CERT_NONE,
    )


if __name__ == "__main__":
    main()
