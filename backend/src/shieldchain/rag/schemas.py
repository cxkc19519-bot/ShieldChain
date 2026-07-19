"""Strict public schemas for the knowledge and RAG API."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


Sensitivity = Literal["public", "internal", "confidential", "restricted"]


class CreateKnowledgeBaseRequest(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    default_sensitivity: Sensitivity = "internal"
    version_policy: str = Field(default="immutable", min_length=1, max_length=64)

    @field_validator("name", "version_policy")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value.strip()


class KnowledgeBaseView(StrictModel):
    id: UUID
    name: str
    status: Literal["draft", "published", "archived", "deleted"]
    default_sensitivity: Sensitivity
    version_policy: str
    created_at: datetime
    updated_at: datetime


class KnowledgeBaseListResponse(StrictModel):
    items: list[KnowledgeBaseView]


class DocumentVersionView(StrictModel):
    id: UUID
    document_id: UUID
    version_number: int
    parsing_status: Literal["pending", "processing", "succeeded", "failed", "ocr_required"]
    chunking_status: Literal["pending", "processing", "succeeded", "failed"]
    index_status: Literal[
        "pending", "processing", "succeeded", "failed", "delete_pending", "deleted"
    ]
    chunking_strategy: str
    chunking_failure_category: str | None = None
    created_at: datetime
    published_at: datetime | None = None


class KnowledgeDocumentView(StrictModel):
    id: UUID
    knowledge_base_id: UUID
    original_filename: str
    media_type: str
    status: Literal["draft", "published", "delete_pending", "deleted"]
    current_version_id: UUID | None
    created_at: datetime
    updated_at: datetime
    versions: list[DocumentVersionView] = Field(default_factory=list)


class KnowledgeDocumentListResponse(StrictModel):
    items: list[KnowledgeDocumentView]


class DocumentVersionListResponse(StrictModel):
    document: KnowledgeDocumentView
    items: list[DocumentVersionView]


class LifecycleOperationResponse(StrictModel):
    operation: Literal["publish", "rollback", "delete", "rebuild"]
    status: Literal["accepted", "completed"]
    document_id: UUID
    version_id: UUID | None = None


class RetrievalRequest(StrictModel):
    query: str = Field(min_length=1, max_length=4096)
    knowledge_base_ids: list[UUID] = Field(min_length=1, max_length=50)
    limit: int = Field(default=10, ge=1, le=50)

    @field_validator("query")
    @classmethod
    def reject_blank_query(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("query must not be blank")
        return value.strip()

    @field_validator("knowledge_base_ids")
    @classmethod
    def reject_duplicate_bases(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("knowledge_base_ids must be unique")
        return value


class RetrievalHitView(StrictModel):
    chunk_id: UUID
    knowledge_base_id: UUID
    document_id: UUID
    document_version_id: UUID
    document_title: str
    excerpt: str
    heading_path: list[str]
    page_number: int | None = Field(default=None, ge=1)
    structural_location: str | None = None
    bm25_score: float | None = Field(default=None, ge=0)
    vector_score: float | None = Field(default=None, ge=0, le=1)
    fusion_score: float = Field(ge=0, le=1)
    reranker_score: float | None = Field(default=None, ge=0, le=1)
    updated_at: datetime
    integrity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CitationView(StrictModel):
    citation_id: str
    knowledge_base_id: UUID
    document_id: UUID
    document_version_id: UUID
    chunk_id: UUID
    document_title: str
    heading_path: list[str]
    page_number: int | None = Field(default=None, ge=1)
    structural_location: str | None = None
    excerpt: str
    bm25_score: float | None = Field(default=None, ge=0)
    vector_score: float | None = Field(default=None, ge=0, le=1)
    fusion_score: float = Field(ge=0, le=1)
    reranker_score: float | None = Field(default=None, ge=0, le=1)
    updated_at: datetime
    integrity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class DegradationView(StrictModel):
    kind: Literal["rewrite_degraded", "vector_degraded", "reranker_degraded"]
    error_category: str
    message: str


class RetrievalResponse(StrictModel):
    query: str
    answer: str | None
    refusal_reason: Literal[
        "insufficient_evidence",
        "conflicting_evidence",
        "stale_evidence",
        "unauthorized",
        "unsafe_content",
    ] | None
    hits: list[RetrievalHitView]
    citations: list[CitationView]
    degradations: list[DegradationView]


class EvaluationRequest(StrictModel):
    dataset_id: str = Field(min_length=1, max_length=128)
    max_cases: int = Field(default=100, ge=1, le=1000)

    @field_validator("dataset_id")
    @classmethod
    def safe_dataset_id(cls, value: str) -> str:
        value = value.strip()
        safe_characters = "abcdefghijklmnopqrstuvwxyz0123456789-_."
        if not value or any(character not in safe_characters for character in value.casefold()):
            raise ValueError("dataset_id contains unsafe characters")
        return value


class EvaluationResponse(StrictModel):
    dataset_id: str
    dataset_version: str
    case_count: int = Field(ge=0)
    metrics: dict[str, int | float]
    quality_gate_passed: bool
