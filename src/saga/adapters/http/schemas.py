"""Pydantic schemas for FastAPI HTTP endpoints."""

from __future__ import annotations

import base64
from pydantic import BaseModel, ConfigDict, Field, field_validator


class BaseSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True, strict=True)


# --- Provider Schemas ---

class UserRegisterRequest(BaseSchema):
    user_id: str
    password: str
    certificate_der_b64: str


class UserRegisterResponse(BaseSchema):
    status: str
    message: str


class RegisteredPublicOtkModel(BaseSchema):
    public_key_b64: str
    user_signature_b64: str


class AgentRegisterRequest(BaseSchema):
    owner_id: str
    password: str
    agent_id: str
    endpoint_type: str
    endpoint_host: str
    endpoint_port: int
    certificate_der_b64: str
    access_control_public_key_b64: str
    contact_policy_document_b64: str
    public_otks: list[RegisteredPublicOtkModel] = Field(min_length=1)
    user_metadata_signature_b64: str


class AgentRegisterResponse(BaseSchema):
    status: str
    message: str


class ContactResolveRequest(BaseSchema):
    pass


class ContactResolveResponse(BaseSchema):
    agent_id: str
    endpoint_type: str
    endpoint_host: str
    endpoint_port: int
    certificate_der_b64: str
    access_control_public_key_b64: str
    contact_policy_document_b64: str
    available_public_otks: list[RegisteredPublicOtkModel]


class StoreSotkRequest(BaseSchema):
    ordinal: int
    secret_key_b64: str


class StoreSotkResponse(BaseSchema):
    status: str


# --- Agent Handshake / Protocol Schemas ---

class AgentHandshakeRequest(BaseSchema):
    initiating_agent_certificate_der_b64: str
    initiating_agent_access_control_public_key_b64: str
    provider_attestation_signature_b64: str
    allocated_otk_ordinal: int
    allocated_otk_public_key_b64: str
    allocated_otk_user_signature_b64: str
    q_max: int
    lifetime_ms: int


class AgentHandshakeResponse(BaseSchema):
    act_version: int
    act_ciphertext_b64: str
    act_nonce_b64: str


class ActUseRequest(BaseSchema):
    act_version: int
    act_ciphertext_b64: str
    act_nonce_b64: str
    initiating_agent_access_control_public_key_b64: str
    action: str
    payload_b64: str = ""


class ActUseResponse(BaseSchema):
    status: str
    result_b64: str
    use_count: int
