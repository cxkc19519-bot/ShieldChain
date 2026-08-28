from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class OperationsReportRequest(BaseModel):
    """The permitted time window for a report; no arbitrary query is accepted."""

    start_at: datetime | None = None
    end_at: datetime | None = None

    @model_validator(mode="after")
    def validate_range(self) -> OperationsReportRequest:
        if self.start_at is not None and self.end_at is not None and self.start_at > self.end_at:
            raise ValueError("start_at must not be later than end_at")
        return self


class McpToolCallView(BaseModel):
    name: str
    label: str
    status: Literal["succeeded", "empty", "failed"]
    reason_code: (
        Literal[
            "tool_dependency_failed",
            "mcp_remote_budget_exhausted",
            "mcp_remote_catalog_expired",
            "mcp_remote_circuit_open",
            "mcp_remote_credentials_missing",
            "mcp_remote_invalid_result",
            "mcp_remote_rate_limited",
            "mcp_remote_request_too_large",
            "mcp_remote_response_too_large",
            "mcp_remote_schema_changed",
            "mcp_remote_timed_out",
            "mcp_remote_tool_error",
            "mcp_remote_unavailable",
        ]
        | None
    ) = None
    arguments: dict[str, str | int]
    result_count: int = Field(ge=0)
    summary: str
    items: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_failure_shape(self) -> McpToolCallView:
        if self.status == "failed":
            if self.reason_code is None or self.result_count != 0 or self.items:
                raise ValueError("failed tool calls require a reason and no result data")
        elif self.reason_code is not None:
            raise ValueError("successful tool calls cannot include a failure reason")
        return self


class ReportStageView(BaseModel):
    key: str
    label: str
    status: Literal["completed", "fallback"]
    detail: str


class ResponsePlanReferenceView(BaseModel):
    plan_id: UUID
    revision_id: UUID
    revision: int = Field(ge=0)
    status: Literal["proposed", "needs_review", "completed_advisory"]
    public_summary: str
    action_count: int = Field(ge=0, le=8)
    generation_status: Literal["model_compiled", "deterministic_fallback"]
    fallback_reason_code: str | None = None
    execution_status: Literal["not_executed"] = "not_executed"


class AgentRoleRunView(BaseModel):
    role: str
    label: str
    status: Literal["completed", "fallback"]
    summary: str
    handoff_to: str | None = None
    iteration: int = 0
    decision_reason: str = ""
    response_plan: ResponsePlanReferenceView | None = None


class OperationsReportView(BaseModel):
    id: str
    run_id: UUID | None = None
    run_status: Literal["completed", "legacy_without_run"] = "legacy_without_run"
    generated_at: datetime
    start_at: datetime
    end_at: datetime
    agent_name: str
    model: str | None = None
    stages: list[ReportStageView]
    collaboration: list[AgentRoleRunView]
    tool_calls: list[McpToolCallView]
    response_plan: ResponsePlanReferenceView | None = None
    markdown: str
    html: str


class OperationsReportListResponse(BaseModel):
    items: list[OperationsReportView]


class AgentToolCallAuditView(BaseModel):
    id: UUID
    run_id: UUID | None
    case_id: UUID | None
    role: str | None
    direction: Literal["internal", "mcp_inbound", "mcp_outbound"]
    provider_kind: Literal["builtin", "rag", "remote_mcp"]
    provider_id: str
    tool_identity: UUID
    tool_alias: str
    catalog_revision: str
    schema_revision: str
    arguments: dict[str, str | int]
    status: Literal[
        "running",
        "succeeded",
        "empty",
        "failed",
        "timed_out",
        "cancelled",
        "rejected",
        "unknown",
    ]
    reason_code: str | None
    result_count: int
    summary: str | None
    duration_ms: int | None
    attempt: int
    result_bytes: int | None
    truncated: bool
    request_id: str
    created_at: datetime
    finished_at: datetime | None


class AgentToolCallAuditListResponse(BaseModel):
    items: list[AgentToolCallAuditView]
