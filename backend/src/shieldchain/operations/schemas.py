from __future__ import annotations

from datetime import datetime
from typing import Literal

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
    evidence_domains: list[str] = Field(default_factory=list)


class ReasoningStepView(BaseModel):
    """公开可审计的调查推理步骤，不包含模型私有思维链。"""

    sequence: int = Field(ge=1)
    phase: str
    title: str
    detail: str
    evidence: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    status: Literal["completed", "pending", "blocked"] = "completed"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class CrossDomainEvidenceView(BaseModel):
    """跨域证据覆盖的白名单投影。"""

    key: str
    label: str
    source: str
    result_count: int = Field(ge=0)
    status: Literal["observed", "not_observed"]
    summary: str


class ClosureLoopView(BaseModel):
    """观测、决策、受控动作、验证和反馈的闭环状态。"""

    status: Literal["analysis_complete", "awaiting_approval", "verification_pending", "closed"]
    observed: str
    decision: str
    action: str
    verification: str
    feedback: str
    human_approval_required: bool = True


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
    reasoning_trace: list[ReasoningStepView] = Field(default_factory=list)
    cross_domain: list[CrossDomainEvidenceView] = Field(default_factory=list)
    closure: ClosureLoopView = Field(
        default_factory=lambda: ClosureLoopView(
            status="analysis_complete",
            observed="尚无结构化调查轨迹。",
            decision="等待人工复核。",
            action="未执行任何安全动作。",
            verification="尚未进入验证阶段。",
            feedback="验证失败时应返回总控重新规划。",
        )
    )
    markdown: str
    html: str


class OperationsReportListResponse(BaseModel):
    items: list[OperationsReportView]
