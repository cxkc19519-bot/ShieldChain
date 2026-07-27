"""FastAPI routes for the SAGA Provider."""

from __future__ import annotations

import base64
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from saga.domain.agents import AgentId, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.users import UserId
from saga.protocols.agent_registration import RegisterAgentCommand
from saga.protocols.user_registration import UserRegistrationService
from saga.protocols.contact_resolution import ContactResolutionService, ResolveContactCommand
from saga.adapters.tls.peer_identity import get_agent_identity
from saga.ports.transactions import AgentCreateOutcome, UserCreateOutcome

from .schemas import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    ContactResolveRequest,
    ContactResolveResponse,
    RegisteredPublicOtkModel,
    UserRegisterRequest,
    UserRegisterResponse,
)


def get_user_registration_service(request: Request) -> UserRegistrationService:
    return request.app.state.user_registration_service


def get_contact_resolution_service(request: Request) -> ContactResolutionService:
    return request.app.state.contact_resolution_service


router = APIRouter()


@router.post("/users/register", response_model=UserRegisterResponse)
async def register_user(
    req: UserRegisterRequest,
    service: UserRegistrationService = Depends(get_user_registration_service),
) -> UserRegisterResponse:
    cert_der = base64.b64decode(req.certificate_der_b64)
    user_id = UserId(req.user_id)
    
    outcome = service.register_user(
        user_id=user_id,
        password=req.password,
        certificate_der=cert_der,
    )
    
    if outcome == UserCreateOutcome.CREATED:
        return UserRegisterResponse(status="success", message="User registered")
    else:
        # Conflicts or bad policies etc might be handled
        return UserRegisterResponse(status="conflict", message="User already exists")


@router.post("/agents/register", response_model=AgentRegisterResponse)
async def register_agent(
    req: AgentRegisterRequest,
    service: UserRegistrationService = Depends(get_user_registration_service),
) -> AgentRegisterResponse:
    
    otks = [
        RegisteredPublicOtk(
            public_key=base64.b64decode(otk.public_key_b64),
            user_signature=base64.b64decode(otk.user_signature_b64),
        )
        for otk in req.public_otks
    ]
    
    command = RegisterAgentCommand(
        owner_id=UserId(req.owner_id),
        password=req.password,
        agent_id=AgentId.from_string(req.agent_id),
        endpoint=EndpointValue(
            device=req.endpoint_type,
            ip=req.endpoint_host,
            port=req.endpoint_port,
        ),
        certificate_der=base64.b64decode(req.certificate_der_b64),
        access_control_public_key=base64.b64decode(req.access_control_public_key_b64),
        contact_policy_document=base64.b64decode(req.contact_policy_document_b64),
        public_otks=tuple(otks),
        user_metadata_signature=base64.b64decode(req.user_metadata_signature_b64),
    )
    
    outcome = service.register_agent(command=command)
    
    if outcome == AgentCreateOutcome.CREATED:
        return AgentRegisterResponse(status="success", message="Agent registered")
    else:
        return AgentRegisterResponse(status="conflict", message="Agent ID conflict")


@router.post("/agents/{agent_id_str}/resolve", response_model=ContactResolveResponse)
async def resolve_contact(
    agent_id_str: str,
    req: ContactResolveRequest,
    # TLS extraction dependency verifies the connecting Agent's identity
    caller_agent_id: AgentId = Depends(get_agent_identity),
    service: ContactResolutionService = Depends(get_contact_resolution_service),
) -> ContactResolveResponse:
    
    target_id = AgentId.from_string(agent_id_str)
    
    command = ResolveContactCommand(
        receiving_agent_id=target_id,
        initiating_agent_id=caller_agent_id,
    )
    
    bundle = service.resolve(command)
    
    # Map back to response
    otks = [
        RegisteredPublicOtkModel(
            public_key_b64=base64.b64encode(otk.public_key).decode("ascii"),
            user_signature_b64=base64.b64encode(otk.user_signature).decode("ascii"),
        )
        for otk in bundle.available_public_otks
    ]
    
    return ContactResolveResponse(
        agent_id=bundle.agent_id.to_string(),
        endpoint_type=bundle.endpoint.device,
        endpoint_host=bundle.endpoint.ip,
        endpoint_port=bundle.endpoint.port,
        certificate_der_b64=base64.b64encode(bundle.certificate_der).decode("ascii"),
        access_control_public_key_b64=base64.b64encode(bundle.access_control_public_key).decode("ascii"),
        contact_policy_document_b64=base64.b64encode(bundle.contact_policy_document).decode("ascii"),
        available_public_otks=otks,
    )


@router.get("/metrics/dashboard")
async def get_dashboard_metrics(request: Request):
    """Expose high-level ecosystem metrics to the Provider Dashboard."""
    
    # In a real system, we'd query a database or emit metrics.
    # For this dashboard demo, we extract lengths from our in-memory registries.
    user_reg_service: UserRegistrationService = request.app.state.user_registration_service
    user_registry = user_reg_service._user_registry
    
    contact_service: ContactResolutionService = request.app.state.contact_resolution_service
    agent_registry = contact_service._contact_state_store
    
    total_users = 0
    total_agents = 0
    
    # We use protective try-except since these are internal representations
    try:
        total_users = len(user_registry._registrations)
    except Exception:
        pass
        
    try:
        total_agents = len(agent_registry._registrations)
    except Exception:
        pass
        
    # Return some interesting simulated metrics for the UI to chart
    return {
        "status": "online",
        "metrics": {
            "total_users": total_users,
            "total_agents": total_agents,
            "active_tokens": total_agents * 5,  # simulated
            "handshakes_24h": total_agents * 12, # simulated
        },
        "agents": [
            {
                "id": str(agent_id.to_string()),
                "owner": str(agent_id.owner.value),
                "status": "online",
                "uptime": "99.9%"
            }
            for agent_id in getattr(agent_registry, "_registrations", {}).keys()
        ]
    }


class SimulateAttackRequest(BaseModel):
    attack_type: str

@router.post("/api/simulate-attack")
async def simulate_attack(req: SimulateAttackRequest):
    import httpx
    import ssl
    from pathlib import Path
    from saga.adapters.tls.config import build_agent_client_ssl_context
    import base64

    attack_type = req.attack_type
    pki_dir = Path("tests/fixtures/pki")
    ca_cert = pki_dir / "ca_cert.pem"
    
    # Simulate Bob attacking Alice
    bob_cert = pki_dir / "agent_b_fullchain.pem"
    bob_key = pki_dir / "agent_b_key.pem"
    
    if not (ca_cert.exists() and bob_cert.exists() and bob_key.exists()):
        return {"status": "error", "message": "PKI certificates not found for simulation."}
        
    ctx = build_agent_client_ssl_context(
        cert_path=bob_cert,
        key_path=bob_key,
        ca_cert_path=ca_cert,
    )
    
    target_url = "https://127.0.0.1:8001"
    headers = {"X-Test-Peer-Identity": "urn:saga:agent:bob:agent-b"}
    
    async with httpx.AsyncClient(verify=ctx) as client:
        try:
            if attack_type == "tamper":
                response = await client.post(
                    f"{target_url}/act/establish",
                    headers=headers,
                    json={
                        "initiating_agent_certificate_der_b64": base64.b64encode(b"\\x02" * 100).decode("ascii"),
                        "initiating_agent_access_control_public_key_b64": base64.b64encode(b"\\x02" * 32).decode("ascii"),
                        "provider_attestation_signature_b64": base64.b64encode(b"\\x02" * 64).decode("ascii"),
                        "allocated_otk_ordinal": 0,
                        "allocated_otk_public_key_b64": base64.b64encode(b"\\x02" * 32).decode("ascii"),
                        "allocated_otk_user_signature_b64": base64.b64encode(b"\\x02" * 64).decode("ascii"),
                        "q_max": 10,
                        "lifetime_ms": 60000,
                    }
                )
                return {"status": response.status_code, "text": response.text, "type": "数据篡改阻断 (Tamper Blocked)"}
                
            elif attack_type == "mitm":
                response = await client.post(
                    f"{target_url}/act/use",
                    headers=headers,
                    json={
                        "act_version": 1,
                        "act_ciphertext_b64": base64.b64encode(b"stolen_ciphertext").decode("ascii"),
                        "act_nonce_b64": base64.b64encode(b"\\x03" * 32).decode("ascii"),
                        "initiating_agent_access_control_public_key_b64": base64.b64encode(b"\\xff" * 32).decode("ascii"),
                        "action": "do_something",
                        "payload_b64": "",
                    }
                )
                return {"status": response.status_code, "text": response.text, "type": "身份绑定阻断 (MITM Blocked)"}
                
            elif attack_type == "replay":
                response = await client.post(
                    f"{target_url}/act/use",
                    headers=headers,
                    json={
                        "act_version": 1,
                        "act_ciphertext_b64": base64.b64encode(b"old_ciphertext").decode("ascii"),
                        "act_nonce_b64": base64.b64encode(b"\\x01" * 32).decode("ascii"),
                        "initiating_agent_access_control_public_key_b64": base64.b64encode(b"\\x02" * 32).decode("ascii"),
                        "action": "transfer_funds",
                        "payload_b64": "",
                    }
                )
                return {"status": response.status_code, "text": response.text, "type": "重放/伪造拦截 (Replay Blocked)"}
                
            else:
                return {"status": 400, "message": "Unknown attack type"}
                
        except httpx.RequestError as e:
            return {"status": "error", "message": f"Network Error: {str(e)}"}
