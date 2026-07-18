from datetime import datetime
from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list[JsonScalar]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StartInvestigationRequest(StrictModel):
    simulation_instance_id: UUID
    mode: Literal["normal", "fail_block_once"] = "normal"


class ResetSimulationRequest(StrictModel):
    pass


class SimulationView(StrictModel):
    id: UUID
    generation: int
    environment: Literal["simulation"]
    connection_status: str
    firewall_status: str
    fail_block_consumed: bool


class IncidentView(StrictModel):
    id: UUID
    external_id: str
    simulation_instance_id: UUID
    alert_id: str
    alert_status: str
    endpoint: str
    username: str
    source_ip: IPv4Address
    remote_ip: IPv4Address
    remote_port: int
    process_name: str
    parent_process_name: str
    command_summary: str
    threat_label: str
    created_at: datetime


class RunSummaryView(StrictModel):
    run_id: UUID
    status: str
    mode: str
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class StepView(StrictModel):
    step_key: str
    status: str
    detail: dict[str, JsonValue]
    error_code: str | None
    started_at: datetime
    completed_at: datetime | None


class EvidenceView(StrictModel):
    id: UUID
    evidence_type: str
    source: str
    observed_at: datetime
    summary: str
    raw_reference: str
    integrity_sha256: str
    confidence: float
    confirmed: bool
    integrity_verified: bool
    payload: dict[str, JsonValue]


class AssessmentView(StrictModel):
    conclusion: str
    risk_level: str
    rule_ids: list[str]
    evidence_ids: list[UUID]
    recommended_action: str | None
    explanation: str


class ToolResultView(StrictModel):
    tool_name: str
    target: str
    idempotency_key: str
    status: str
    before_state: dict[str, JsonValue]
    after_state: dict[str, JsonValue]
    error_code: str | None


class VerificationView(StrictModel):
    blocked: bool
    connection_stopped: bool
    observed_at: datetime
    evidence_ids: list[UUID]


class ResetSimulationResponse(StrictModel):
    simulation: SimulationView
    incident: IncidentView


class InvestigationResponse(StrictModel):
    run_id: UUID
    incident_id: UUID
    simulation_instance_id: UUID
    status: str
    mode: str
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    simulation: SimulationView
    steps: list[StepView]
    evidence: list[EvidenceView]
    assessment: AssessmentView | None
    tool_result: ToolResultView | None
    verification: VerificationView | None


class IncidentResponse(StrictModel):
    incident: IncidentView
    runs: list[RunSummaryView]


class AuditEventView(StrictModel):
    id: UUID
    sequence: int
    event_type: str
    request_id: str
    occurred_at: datetime
    payload: dict[str, JsonValue]


class AuditResponse(StrictModel):
    incident_id: UUID
    events: list[AuditEventView]
