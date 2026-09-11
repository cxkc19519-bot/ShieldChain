from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WazuhAlertInput(StrictModel):
    """Minimum normalized evidence accepted from the Manager-side adapter."""

    external_id: str = Field(min_length=1, max_length=256)
    occurred_at: datetime
    severity: int = Field(ge=0, le=15)
    rule_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    agent_id: str | None = Field(default=None, max_length=128)
    agent_name: str | None = Field(default=None, max_length=256)
    mitre_ids: tuple[str, ...] = Field(default=(), max_length=32)
    process_name: str | None = Field(default=None, max_length=512)
    parent_process_name: str | None = Field(default=None, max_length=512)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value.astimezone(UTC)

    @field_validator("mitre_ids")
    @classmethod
    def validate_mitre_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(dict.fromkeys(item.strip() for item in value))
        if any(not item or len(item) > 32 for item in cleaned):
            raise ValueError("mitre_ids contains an invalid value")
        return cleaned


class WazuhTriageAssessmentView(StrictModel):
    """Public, reviewable output from the existing alert-triage specialist."""

    run_id: UUID
    agent_name: Literal["告警分诊智能体"] = "告警分诊智能体"
    model: str | None = None
    summary: str
    decision_reason: str
    limitation: str = "智能体输出是研判建议，不是误报结论；最终定性必须由分析员确认。"


class WazuhCaseDispositionView(StrictModel):
    id: UUID
    case_id: UUID
    run_id: UUID
    decision: Literal["false_positive", "true_positive", "needs_more_evidence"]
    reason_code: Literal[
        "expected_activity",
        "authorized_test",
        "duplicate_detection",
        "rule_too_broad",
        "confirmed_malicious",
        "insufficient_context",
        "other",
    ]
    rationale: str
    suppression_scope: Literal["none", "same_rule_endpoint", "same_rule"] = "none"
    suppression_status: Literal[
        "not_requested", "proposed_only", "active", "expired", "revoked"
    ] = "not_requested"
    suppression_expires_at: datetime | None = None
    reviewer_id: UUID
    created_at: datetime


class WazuhCaseDispositionRequest(StrictModel):
    decision: Literal["false_positive", "true_positive", "needs_more_evidence"]
    reason_code: Literal[
        "expected_activity",
        "authorized_test",
        "duplicate_detection",
        "rule_too_broad",
        "confirmed_malicious",
        "insufficient_context",
        "other",
    ]
    rationale: str = Field(min_length=1, max_length=1000)
    suppression_scope: Literal["none", "same_rule_endpoint", "same_rule"] = "none"
    suppression_expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_disposition(self) -> WazuhCaseDispositionRequest:
        allowed_reasons = {
            "false_positive": {
                "expected_activity",
                "authorized_test",
                "duplicate_detection",
                "rule_too_broad",
                "other",
            },
            "true_positive": {"confirmed_malicious", "other"},
            "needs_more_evidence": {"insufficient_context", "other"},
        }
        if self.reason_code not in allowed_reasons[self.decision]:
            raise ValueError("reason_code does not match the selected decision")
        if self.suppression_scope != "none" and self.decision != "false_positive":
            raise ValueError("suppression can only be proposed for a confirmed false positive")
        if self.suppression_scope == "none" and self.suppression_expires_at is not None:
            raise ValueError("suppression expiry requires a suppression scope")
        if self.suppression_expires_at is not None:
            if (
                self.suppression_expires_at.tzinfo is None
                or self.suppression_expires_at.utcoffset() is None
            ):
                raise ValueError("suppression_expires_at must include a timezone")
            self.suppression_expires_at = self.suppression_expires_at.astimezone(UTC)
        return self


class WazuhFalsePositiveMetricsView(StrictModel):
    reviewed_cases: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    needs_more_evidence: int = Field(ge=0)
    false_positive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    proposed_suppressions: int = Field(ge=0)
    active_suppressions: int = Field(ge=0)
    suppressed_alerts: int = Field(ge=0)


class WazuhSuppressionPolicyView(StrictModel):
    id: UUID
    source_case_id: UUID
    source_disposition_id: UUID
    rule_id: str
    endpoint: str | None
    scope: Literal["same_rule_endpoint", "same_rule"]
    status: Literal["active", "expired", "revoked"]
    rationale: str
    expires_at: datetime
    approved_by: UUID
    approved_at: datetime


class WazuhSuppressionMatchView(StrictModel):
    id: UUID
    policy_id: UUID
    scope: Literal["same_rule_endpoint", "same_rule"]
    rule_id: str
    endpoint: str
    matched_at: datetime
    expires_at: datetime


class WazuhReviewCaseView(StrictModel):
    id: UUID
    tracking_id: str
    alert_id: UUID
    source: Literal["wazuh"] = "wazuh"
    status: Literal[
        "needs_review", "investigating", "investigated", "investigation_failed"
    ] = "needs_review"
    run_id: UUID | None = None
    severity: int
    rule_id: str
    title: str
    endpoint: str
    created_at: datetime
    updated_at: datetime
    triage_assessment: WazuhTriageAssessmentView | None = None
    disposition: WazuhCaseDispositionView | None = None


class WazuhAlertView(StrictModel):
    id: UUID
    external_id: str
    occurred_at: datetime
    severity: int
    rule_id: str
    title: str
    agent_name: str | None
    mitre_ids: tuple[str, ...]
    process_name: str | None
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    received_at: datetime
    created: bool = True
    review_case: WazuhReviewCaseView | None = None
    suppression: WazuhSuppressionMatchView | None = None


class WazuhAlertListResponse(StrictModel):
    items: list[WazuhAlertView]


class WazuhReviewCaseListResponse(StrictModel):
    items: list[WazuhReviewCaseView]


class WazuhInvestigationRequest(StrictModel):
    """Manual fallback request for deployments without automatic investigation."""

    rule_ttl_seconds: int = Field(default=60, ge=60, le=86_400)
