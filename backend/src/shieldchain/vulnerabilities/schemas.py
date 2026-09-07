from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


Severity = Literal["critical", "high", "medium", "low", "informational"]
FindingStatus = Literal[
    "new",
    "triaged",
    "remediation_approved",
    "remediation_in_progress",
    "verification_pending",
    "closed",
    "accepted_risk",
]


class VulnerabilityFindingIngestRequest(StrictModel):
    external_id: str = Field(min_length=1, max_length=256)
    scanner: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)
    asset_name: str = Field(min_length=1, max_length=256)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,8}$")
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    package_name: str | None = Field(default=None, max_length=256)
    installed_version: str | None = Field(default=None, max_length=128)
    fixed_version: str | None = Field(default=None, max_length=128)
    observed_at: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("external_id", "scanner", "asset_id", "asset_name")
    @classmethod
    def strip_required(cls, value: str) -> str:
        return value.strip()

    @field_validator("cve_id")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        return value.upper()


class VulnerabilityWorkflowEventView(StrictModel):
    id: UUID
    event_type: str
    actor_type: Literal["scanner", "agent", "human", "system"]
    from_status: FindingStatus | None
    to_status: FindingStatus
    reason_code: str
    summary: str
    details: dict[str, Any]
    created_at: datetime


class VulnerabilityFindingView(StrictModel):
    id: UUID
    scanner: str
    external_id: str
    asset_id: str
    asset_name: str
    cve_id: str
    severity: Severity
    cvss_score: float | None
    package_name: str | None
    installed_version: str | None
    fixed_version: str | None
    status: FindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    latest_triage: VulnerabilityWorkflowEventView | None = None
    events: list[VulnerabilityWorkflowEventView] = Field(default_factory=list)


class VulnerabilityFindingIngestResponse(StrictModel):
    created: bool
    finding: VulnerabilityFindingView


class VulnerabilityFindingListResponse(StrictModel):
    items: list[VulnerabilityFindingView]


class VulnerabilityMetricsView(StrictModel):
    total: int
    open: int
    critical_open: int
    awaiting_approval: int
    verification_pending: int
    closed: int
    accepted_risk: int


class VulnerabilityTriageRequest(StrictModel):
    business_context: str | None = Field(default=None, max_length=1000)


class VulnerabilityDecisionRequest(StrictModel):
    outcome: Literal["approve_remediation", "accept_risk", "mark_not_affected"]
    reason_code: Literal[
        "confirmed_exposure",
        "compensating_control",
        "business_exception",
        "version_not_affected",
        "scanner_false_positive",
        "other",
    ]
    rationale: str = Field(min_length=10, max_length=1000)
    risk_expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_risk_expiry(self) -> VulnerabilityDecisionRequest:
        allowed_reasons = {
            "approve_remediation": {"confirmed_exposure", "other"},
            "accept_risk": {"compensating_control", "business_exception", "other"},
            "mark_not_affected": {"version_not_affected", "scanner_false_positive", "other"},
        }
        if self.reason_code not in allowed_reasons[self.outcome]:
            raise ValueError("reason code does not match the decision")
        if self.outcome == "accept_risk" and self.risk_expires_at is None:
            raise ValueError("accepted risk requires an expiry")
        if self.outcome != "accept_risk" and self.risk_expires_at is not None:
            raise ValueError("risk expiry is only valid for accepted risk")
        return self


class VulnerabilityChangeRequest(StrictModel):
    change_ticket: str = Field(min_length=3, max_length=128)
    implementer: str = Field(min_length=2, max_length=128)
    planned_at: datetime
    plan_summary: str = Field(min_length=10, max_length=1000)


class VulnerabilityImplementationRequest(StrictModel):
    change_ticket: str = Field(min_length=3, max_length=128)
    implementation_summary: str = Field(min_length=10, max_length=1000)
    evidence_references: list[str] = Field(min_length=1, max_length=20)

    @field_validator("evidence_references")
    @classmethod
    def validate_evidence_references(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 512 for item in normalized):
            raise ValueError("evidence references must be non-blank and at most 512 characters")
        return normalized


class VulnerabilityVerificationRequest(StrictModel):
    result: Literal["passed", "failed"]
    scanner: str = Field(min_length=1, max_length=128)
    observed_version: str | None = Field(default=None, max_length=128)
    evidence_references: list[str] = Field(min_length=1, max_length=20)
    summary: str = Field(min_length=10, max_length=1000)

    @field_validator("evidence_references")
    @classmethod
    def validate_evidence_references(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 512 for item in normalized):
            raise ValueError("evidence references must be non-blank and at most 512 characters")
        return normalized


class VulnerabilityMutationView(StrictModel):
    finding: VulnerabilityFindingView
    event: VulnerabilityWorkflowEventView
