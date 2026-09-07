"""Schemas for the persistent grounded assistant."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssistantChatRequest(StrictModel):
    message: str = Field(min_length=1, max_length=4096)
    conversation_id: UUID | None = None

    @field_validator("message")
    @classmethod
    def non_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("message must not be blank")
        return value


class AssistantCitationView(StrictModel):
    index: int = Field(ge=1)
    knowledge_base_id: UUID | None = None
    document_id: UUID | None = None
    document_version_id: UUID | None = None
    chunk_id: UUID | None = None
    document_title: str
    excerpt: str
    heading_path: list[str] = Field(default_factory=list)
    page_number: int | None = Field(default=None, ge=1)
    structural_location: str | None = None
    fusion_score: float = Field(ge=0, le=1)
    updated_at: datetime | None = None
    integrity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    verified_at: date | None = None
    review_due_at: date | None = None
    source_tiers: list[str] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)


AssistantGroundingStatus = Literal[
    "not_applicable",
    "conversational",
    "grounded",
    "extractive_degraded",
    "refused",
    "legacy",
]
AssistantRefusalReason = Literal[
    "insufficient_evidence",
    "conflicting_evidence",
    "stale_evidence",
    "unauthorized",
    "unsafe_content",
]


class AssistantDegradationView(StrictModel):
    kind: Literal[
        "rewrite_degraded",
        "vector_degraded",
        "reranker_degraded",
        "generation_degraded",
    ]
    error_category: str
    message: str


class AssistantMessageView(StrictModel):
    id: UUID
    role: Literal["user", "assistant"]
    content: str
    citations: list[AssistantCitationView] = Field(default_factory=list)
    grounding_status: AssistantGroundingStatus = "legacy"
    refusal_reason: AssistantRefusalReason | None = None
    degradations: list[AssistantDegradationView] = Field(default_factory=list)
    model: str | None = None
    created_at: datetime



class AssistantConversationRenameRequest(StrictModel):
    title: str = Field(min_length=1, max_length=80)

    @field_validator("title")
    @classmethod
    def non_blank_title(cls, value: str) -> str:
        value = value.replace("\n", " ").strip()
        if not value:
            raise ValueError("title must not be blank")
        return value


class AssistantConversationPinRequest(StrictModel):
    pinned: bool

class AssistantConversationView(StrictModel):
    id: UUID
    title: str
    created_at: datetime
    updated_at: datetime
    memory_summary: str
    summary: str
    pinned: bool = False
    message_count: int = Field(ge=0)


class AssistantConversationDetail(AssistantConversationView):
    messages: list[AssistantMessageView] = Field(default_factory=list)


class AssistantConversationListResponse(StrictModel):
    items: list[AssistantConversationView] = Field(default_factory=list)


class AssistantChatResponse(StrictModel):
    conversation_id: UUID
    answer: str
    model: str | None = None
    citations: list[AssistantCitationView] = Field(default_factory=list)
    grounding_status: AssistantGroundingStatus
    refusal_reason: AssistantRefusalReason | None = None
    degradations: list[AssistantDegradationView] = Field(default_factory=list)
    report_documents_synced: int = Field(ge=0)
    memory_summary: str


class AssistantEvaluationRequest(StrictModel):
    dataset_id: str = Field(default="shieldchain-assistant-v1", min_length=1, max_length=128)
    max_cases: int = Field(default=100, ge=1, le=1_000)

    @field_validator("dataset_id")
    @classmethod
    def safe_dataset_id(cls, value: str) -> str:
        value = value.strip().casefold()
        allowed = "abcdefghijklmnopqrstuvwxyz0123456789-_."
        if not value or any(character not in allowed for character in value):
            raise ValueError("dataset_id contains unsafe characters")
        return value


class AssistantEvaluationCaseView(StrictModel):
    case_id: str
    language: Literal["zh", "en"]
    message: str
    expected_statuses: list[AssistantGroundingStatus]
    actual_status: AssistantGroundingStatus
    expected_refusal_reason: AssistantRefusalReason | None = None
    actual_refusal_reason: AssistantRefusalReason | None = None
    expected_document_ids: list[str]
    cited_document_ids: list[str]
    citation_recall: float | None = Field(default=None, ge=0, le=1)
    provenance_completeness: float | None = Field(default=None, ge=0, le=1)
    latency_ms: float = Field(ge=0)
    passed: bool
    failure_reasons: list[str] = Field(default_factory=list)


class AssistantEvaluationResponse(StrictModel):
    dataset_id: str
    dataset_version: str
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_count: int = Field(ge=1)
    metrics: dict[str, float]
    thresholds: dict[str, float]
    case_results: list[AssistantEvaluationCaseView]
    quality_gate_passed: bool
