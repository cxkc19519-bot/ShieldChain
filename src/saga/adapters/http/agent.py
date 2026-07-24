"""FastAPI routes for the SAGA Agent server."""

from __future__ import annotations

import base64
from fastapi import APIRouter, Depends, Request

from saga.domain.agents import AgentId
from saga.protocols.act_establishment import ActEstablishmentService
from saga.protocols.act_use import ActUseService
from saga.domain.act import ActEnvelope, EstablishActCommand, UseActCommand
from saga.adapters.tls.peer_identity import get_agent_identity

from .schemas import (
    ActUseRequest,
    ActUseResponse,
    AgentHandshakeRequest,
    AgentHandshakeResponse,
)


def get_act_establishment_service(request: Request) -> ActEstablishmentService:
    return request.app.state.act_establishment_service


def get_act_use_service(request: Request) -> ActUseService:
    return request.app.state.act_use_service


router = APIRouter()


@router.post("/act/establish", response_model=AgentHandshakeResponse)
async def establish_act(
    req: AgentHandshakeRequest,
    initiating_agent_id: AgentId = Depends(get_agent_identity),
    service: ActEstablishmentService = Depends(get_act_establishment_service),
) -> AgentHandshakeResponse:
    
    # EstablishActCommand handles the Phase 4 logic
    command = EstablishActCommand(
        initiating_agent_certificate_der=base64.b64decode(req.initiating_agent_certificate_der_b64),
        initiating_agent_access_control_public_key=base64.b64decode(req.initiating_agent_access_control_public_key_b64),
        provider_attestation_signature=base64.b64decode(req.provider_attestation_signature_b64),
        allocated_otk_public_key=base64.b64decode(req.allocated_otk_public_key_b64),
        allocated_otk_user_signature=base64.b64decode(req.allocated_otk_user_signature_b64),
        q_max=req.q_max,
        lifetime_ms=req.lifetime_ms,
    )
    
    envelope = service.establish(
        receiver_id=request.app.state.local_agent_id,
        base_command=command,
    )
    
    return AgentHandshakeResponse(
        act_version=envelope.version,
        act_ciphertext_b64=base64.b64encode(envelope.ciphertext).decode("ascii"),
        act_nonce_b64=base64.b64encode(envelope.nonce).decode("ascii"),
    )


@router.post("/act/use", response_model=ActUseResponse)
async def use_act(
    req: ActUseRequest,
    initiating_agent_id: AgentId = Depends(get_agent_identity),
    service: ActUseService = Depends(get_act_use_service),
    request: Request = None,  # Provided by FastAPI automatically if named request
) -> ActUseResponse:
    
    envelope = ActEnvelope(
        version=req.act_version,
        ciphertext=base64.b64decode(req.act_ciphertext_b64),
        nonce=base64.b64decode(req.act_nonce_b64),
    )
    
    command = UseActCommand(
        envelope=envelope,
        initiating_agent_access_control_public_key=base64.b64decode(req.initiating_agent_access_control_public_key_b64),
    )
    
    # In SAGA, ActUseService processes the command. We don't have a payload validation built into it yet,
    # it just returns the state / use_count.
    result = service.use(command=command)
    
    return ActUseResponse(
        status="success",
        result_b64=base64.b64encode(b"Action Completed: " + req.action.encode()).decode("ascii"),
        use_count=result.use_count,
    )
