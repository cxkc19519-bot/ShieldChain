from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class OperationsReportRequest(BaseModel):
    """The permitted time window for a report; no arbitrary query is accepted."""

    start_at: datetime | None = None
    end_at: datetime | None = None

    @model_validator(mode="after")
    def validate_range(self) -> "OperationsReportRequest":
        if self.start_at is not None and self.end_at is not None and self.start_at > self.end_at:
            raise ValueError("start_at must not be later than end_at")
        return self


class McpToolCallView(BaseModel):
    name: str
    label: str
    status: Literal["succeeded", "empty"]
    arguments: dict[str, str | int]
    result_count: int = Field(ge=0)
    summary: str
    items: list[str] = Field(default_factory=list)


class ReportStageView(BaseModel):
    key: str
    label: str
    status: Literal["completed", "fallback"]
    detail: str


class AgentRoleRunView(BaseModel):
    role: str
    label: str
    status: Literal["completed", "fallback"]
    summary: str
    handoff_to: str | None = None
    iteration: int = 0
    decision_reason: str = ""


class OperationsReportView(BaseModel):
    id: str
    generated_at: datetime
    start_at: datetime
    end_at: datetime
    agent_name: str
    model: str | None = None
    stages: list[ReportStageView]
    collaboration: list[AgentRoleRunView]
    tool_calls: list[McpToolCallView]
    markdown: str
    html: str


class OperationsReportListResponse(BaseModel):
    items: list[OperationsReportView]
