from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID


class SensitivityLevel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class KnowledgeBaseStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"
    DELETED = "deleted"


class DocumentStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    DELETE_PENDING = "delete_pending"
    DELETED = "deleted"


class ParsingStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OCR_REQUIRED = "ocr_required"


class ChunkingStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class IndexStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DELETE_PENDING = "delete_pending"
    DELETED = "deleted"


class RetrievalDegradationKind(StrEnum):
    REWRITE_DEGRADED = "rewrite_degraded"
    VECTOR_DEGRADED = "vector_degraded"
    RERANKER_DEGRADED = "reranker_degraded"


class RefusalReason(StrEnum):
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    STALE_EVIDENCE = "stale_evidence"
    UNAUTHORIZED = "unauthorized"
    UNSAFE_CONTENT = "unsafe_content"


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
CHUNKING_FAILURE_CATEGORIES = frozenset(
    {
        "authentication",
        "boundary_empty",
        "boundary_limit",
        "boundary_omission",
        "boundary_order",
        "boundary_out_of_range",
        "boundary_overlap",
        "candidate_integrity",
        "candidate_limit",
        "content_hash_collision",
        "duplicate_output",
        "empty_candidates",
        "llm_error",
        "malformed_json",
        "prompt_limit",
        "rate_limit",
        "response_error",
        "response_limit",
        "schema_error",
        "source_overlap",
        "timeout",
        "token_limit",
        "unavailable",
    }
)


def _require_uuid(value: UUID, field_name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{field_name} must be a UUID")


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_aware_utc(value: datetime, field_name: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{field_name} must be an aware UTC datetime")


def _require_sha256(value: str, field_name: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hexadecimal characters")


def _freeze_strings(
    values: Iterable[str], field_name: str, *, allow_empty: bool = False
) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError(f"{field_name} must be an iterable of strings")
    try:
        frozen = frozenset(values)
    except TypeError as error:
        raise TypeError(f"{field_name} must be iterable") from error
    if not frozen and not allow_empty:
        raise ValueError(f"{field_name} must not be empty")
    for value in frozen:
        _require_non_empty(value, field_name)
    return frozen


def _freeze_uuids(values: Iterable[UUID], field_name: str) -> frozenset[UUID]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{field_name} must be an iterable of UUIDs")
    try:
        frozen = frozenset(values)
    except TypeError as error:
        raise TypeError(f"{field_name} must be iterable") from error
    for value in frozen:
        _require_uuid(value, field_name)
    return frozen


def _freeze_heading_path(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError("heading_path must be an iterable of strings")
    try:
        path = tuple(values)
    except TypeError as error:
        raise TypeError("heading_path must be iterable") from error
    if not path:
        raise ValueError("heading_path must not be empty")
    for value in path:
        _require_non_empty(value, "heading_path")
    return path


def _require_score(value: float | None, field_name: str, *, required: bool = False) -> None:
    if value is None and not required:
        return
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{field_name} must be a finite score between 0 and 1")
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class AccessScope:
    """A server-created, non-expandable authorization boundary for retrieval."""

    tenant_id: UUID
    principal_id: UUID
    roles: Iterable[str]
    allowed_sensitivities: Iterable[SensitivityLevel]
    permission_tags: Iterable[str]
    knowledge_base_ids: Iterable[UUID]

    def __post_init__(self) -> None:
        _require_uuid(self.tenant_id, "tenant_id")
        _require_uuid(self.principal_id, "principal_id")
        object.__setattr__(self, "roles", _freeze_strings(self.roles, "roles"))
        try:
            sensitivities = frozenset(self.allowed_sensitivities)
        except TypeError as error:
            raise TypeError("allowed_sensitivities must be iterable") from error
        if not sensitivities:
            raise ValueError("allowed_sensitivities must not be empty")
        if not all(isinstance(value, SensitivityLevel) for value in sensitivities):
            raise TypeError("allowed_sensitivities must contain SensitivityLevel values")
        object.__setattr__(self, "allowed_sensitivities", sensitivities)
        object.__setattr__(
            self, "permission_tags", _freeze_strings(self.permission_tags, "permission_tags")
        )
        object.__setattr__(
            self, "knowledge_base_ids", _freeze_uuids(self.knowledge_base_ids, "knowledge_base_ids")
        )

    def allows(
        self,
        tenant_id: UUID,
        knowledge_base_id: UUID,
        sensitivity: SensitivityLevel,
        permission_tags: Iterable[str],
    ) -> bool:
        """Return true only for access granted before retrieval; never infer grants from a hit."""
        _require_uuid(tenant_id, "tenant_id")
        _require_uuid(knowledge_base_id, "knowledge_base_id")
        if not isinstance(sensitivity, SensitivityLevel):
            raise TypeError("sensitivity must be a SensitivityLevel")
        required_tags = _freeze_strings(permission_tags, "permission_tags", allow_empty=True)
        return (
            tenant_id == self.tenant_id
            and knowledge_base_id in self.knowledge_base_ids
            and sensitivity in self.allowed_sensitivities
            and required_tags.issubset(self.permission_tags)
        )


@dataclass(frozen=True, slots=True)
class KnowledgeBase:
    id: UUID
    tenant_id: UUID
    name: str
    status: KnowledgeBaseStatus
    default_sensitivity: SensitivityLevel
    version_policy: str
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        _require_uuid(self.tenant_id, "tenant_id")
        _require_non_empty(self.name, "name")
        _require_non_empty(self.version_policy, "version_policy")
        if not isinstance(self.status, KnowledgeBaseStatus):
            raise TypeError("status must be a KnowledgeBaseStatus")
        if not isinstance(self.default_sensitivity, SensitivityLevel):
            raise TypeError("default_sensitivity must be a SensitivityLevel")
        _require_aware_utc(self.created_at, "created_at")
        _require_aware_utc(self.updated_at, "updated_at")


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    id: UUID
    knowledge_base_id: UUID
    tenant_id: UUID
    original_filename: str
    storage_key: str
    media_type: str
    content_sha256: str
    status: DocumentStatus
    current_version_id: UUID | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("id", "knowledge_base_id", "tenant_id"):
            _require_uuid(getattr(self, field_name), field_name)
        for field_name in ("original_filename", "storage_key", "media_type"):
            _require_non_empty(getattr(self, field_name), field_name)
        _require_sha256(self.content_sha256, "content_sha256")
        if not isinstance(self.status, DocumentStatus):
            raise TypeError("status must be a DocumentStatus")
        if self.current_version_id is not None:
            _require_uuid(self.current_version_id, "current_version_id")
        if self.status is DocumentStatus.PUBLISHED and self.current_version_id is None:
            raise ValueError("published documents must have a current_version_id")
        _require_aware_utc(self.created_at, "created_at")
        _require_aware_utc(self.updated_at, "updated_at")


@dataclass(frozen=True, slots=True)
class DocumentVersion:
    id: UUID
    document_id: UUID
    version_number: int
    parsing_status: ParsingStatus
    chunking_status: ChunkingStatus
    index_status: IndexStatus
    parser_name: str
    parser_version: str
    chunking_strategy: str
    chunking_prompt_version: str | None
    chunking_model: str | None
    created_at: datetime
    published_at: datetime | None
    chunking_failure_category: str | None = None
    chunking_retry_key: str | None = None
    chunking_requested_model: str | None = None

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        _require_uuid(self.document_id, "document_id")
        if not isinstance(self.version_number, int) or isinstance(self.version_number, bool):
            raise ValueError("version_number must be at least 1")
        if self.version_number < 1:
            raise ValueError("version_number must be at least 1")
        if not isinstance(self.parsing_status, ParsingStatus):
            raise TypeError("parsing_status must be a ParsingStatus")
        if not isinstance(self.chunking_status, ChunkingStatus):
            raise TypeError("chunking_status must be a ChunkingStatus")
        if not isinstance(self.index_status, IndexStatus):
            raise TypeError("index_status must be an IndexStatus")
        for field_name in ("parser_name", "parser_version", "chunking_strategy"):
            _require_non_empty(getattr(self, field_name), field_name)
        for field_name in ("chunking_prompt_version", "chunking_model"):
            value = getattr(self, field_name)
            if value is not None:
                _require_non_empty(value, field_name)
        _require_aware_utc(self.created_at, "created_at")
        if self.published_at is not None:
            _require_aware_utc(self.published_at, "published_at")
        if self.chunking_failure_category is not None:
            _require_non_empty(self.chunking_failure_category, "chunking_failure_category")
            if self.chunking_failure_category not in CHUNKING_FAILURE_CATEGORIES:
                raise ValueError("chunking_failure_category is not a safe category")
        if self.chunking_retry_key is not None:
            _require_sha256(self.chunking_retry_key, "chunking_retry_key")
        if self.chunking_requested_model is not None:
            _require_non_empty(self.chunking_requested_model, "chunking_requested_model")
            if len(self.chunking_requested_model) > 128:
                raise ValueError("chunking_requested_model must not exceed 128 characters")


@dataclass(frozen=True, slots=True)
class ChunkSource:
    """One immutable occurrence of a chunk in deterministic parsed content."""

    chunk_id: UUID
    occurrence_ordinal: int
    parsed_element_ordinal: int
    start_offset: int
    end_offset: int
    heading_path: Iterable[str]
    page_number: int | None
    structural_location: str | None

    def __post_init__(self) -> None:
        _require_uuid(self.chunk_id, "chunk_id")
        for field_name in ("occurrence_ordinal", "parsed_element_ordinal", "start_offset"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if (
            not isinstance(self.end_offset, int)
            or isinstance(self.end_offset, bool)
            or self.end_offset <= self.start_offset
        ):
            raise ValueError("end_offset must be greater than start_offset")
        object.__setattr__(self, "heading_path", _freeze_heading_path(self.heading_path))
        if self.page_number is not None and (
            not isinstance(self.page_number, int)
            or isinstance(self.page_number, bool)
            or self.page_number < 1
        ):
            raise ValueError("page_number must be at least 1")
        if self.structural_location is not None:
            _require_non_empty(self.structural_location, "structural_location")
            if len(self.structural_location) > 512:
                raise ValueError("structural_location must not exceed 512 characters")
        if self.page_number is None and self.structural_location is None:
            raise ValueError("a chunk source must include a page_number or structural_location")


@dataclass(frozen=True, slots=True)
class KnowledgeChunk:
    id: UUID
    document_version_id: UUID
    ordinal: int
    heading_path: Iterable[str]
    page_number: int | None
    structural_location: str | None
    text: str
    token_count: int
    content_sha256: str
    sensitivity: SensitivityLevel
    permission_tags: Iterable[str]
    chunking_mode: str
    is_degraded: bool
    sources: Iterable[ChunkSource] = ()

    def __post_init__(self) -> None:
        _require_uuid(self.id, "id")
        _require_uuid(self.document_version_id, "document_version_id")
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool) or self.ordinal < 0:
            raise ValueError("ordinal must be at least 0")
        object.__setattr__(self, "heading_path", _freeze_heading_path(self.heading_path))
        if self.page_number is not None and (
            not isinstance(self.page_number, int)
            or isinstance(self.page_number, bool)
            or self.page_number < 1
        ):
            raise ValueError("page_number must be at least 1")
        if self.structural_location is not None:
            _require_non_empty(self.structural_location, "structural_location")
            if len(self.structural_location) > 512:
                raise ValueError("structural_location must not exceed 512 characters")
        if self.page_number is None and self.structural_location is None:
            raise ValueError("a chunk must include a page_number or structural_location")
        _require_non_empty(self.text, "text")
        if (
            not isinstance(self.token_count, int)
            or isinstance(self.token_count, bool)
            or self.token_count < 1
        ):
            raise ValueError("token_count must be at least 1")
        _require_sha256(self.content_sha256, "content_sha256")
        if not isinstance(self.sensitivity, SensitivityLevel):
            raise TypeError("sensitivity must be a SensitivityLevel")
        object.__setattr__(
            self, "permission_tags", _freeze_strings(self.permission_tags, "permission_tags")
        )
        _require_non_empty(self.chunking_mode, "chunking_mode")
        if not isinstance(self.is_degraded, bool):
            raise TypeError("is_degraded must be a bool")
        try:
            sources = tuple(self.sources)
        except TypeError as error:
            raise TypeError("sources must be iterable") from error
        if not all(isinstance(source, ChunkSource) for source in sources):
            raise TypeError("sources must contain ChunkSource values")
        if any(source.chunk_id != self.id for source in sources):
            raise ValueError("each chunk source must belong to this chunk")
        if len({source.occurrence_ordinal for source in sources}) != len(sources):
            raise ValueError("chunk source occurrence ordinals must be unique")
        object.__setattr__(self, "sources", sources)


@dataclass(frozen=True, slots=True)
class IndexRecord:
    id: UUID
    document_version_id: UUID
    chunk_id: UUID
    bm25_key: str | None
    embedding_model: str | None
    vector_id: str | None
    reranker_model: str | None
    index_version: str
    status: IndexStatus
    error_category: str | None
    updated_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("id", "document_version_id", "chunk_id"):
            _require_uuid(getattr(self, field_name), field_name)
        for field_name in (
            "bm25_key",
            "embedding_model",
            "vector_id",
            "reranker_model",
            "error_category",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _require_non_empty(value, field_name)
        _require_non_empty(self.index_version, "index_version")
        if not isinstance(self.status, IndexStatus):
            raise TypeError("status must be an IndexStatus")
        _require_aware_utc(self.updated_at, "updated_at")


@dataclass(frozen=True, slots=True)
class Citation:
    knowledge_base_id: UUID
    document_id: UUID
    document_version_id: UUID
    chunk_id: UUID
    heading_path: Iterable[str]
    page_number: int | None
    structural_location: str | None
    excerpt: str
    bm25_score: float | None
    vector_score: float | None
    fusion_score: float
    reranker_score: float | None
    updated_at: datetime
    integrity_sha256: str

    def __post_init__(self) -> None:
        for field_name in ("knowledge_base_id", "document_id", "document_version_id", "chunk_id"):
            _require_uuid(getattr(self, field_name), field_name)
        object.__setattr__(self, "heading_path", _freeze_heading_path(self.heading_path))
        if self.page_number is not None and (
            not isinstance(self.page_number, int)
            or isinstance(self.page_number, bool)
            or self.page_number < 1
        ):
            raise ValueError("page_number must be at least 1")
        if self.structural_location is not None:
            _require_non_empty(self.structural_location, "structural_location")
        if self.page_number is None and self.structural_location is None:
            raise ValueError("a citation must include a page_number or structural_location")
        _require_non_empty(self.excerpt, "excerpt")
        _require_score(self.bm25_score, "bm25_score")
        _require_score(self.vector_score, "vector_score")
        _require_score(self.fusion_score, "fusion_score", required=True)
        _require_score(self.reranker_score, "reranker_score")
        _require_aware_utc(self.updated_at, "updated_at")
        _require_sha256(self.integrity_sha256, "integrity_sha256")


@dataclass(frozen=True, slots=True)
class RetrievalDegradation:
    kind: RetrievalDegradationKind
    error_category: str
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RetrievalDegradationKind):
            raise TypeError("kind must be a RetrievalDegradationKind")
        _require_non_empty(self.error_category, "error_category")
        _require_non_empty(self.message, "message")


@dataclass(frozen=True, slots=True)
class StructuredRefusal:
    reason: RefusalReason
    message: str
    original_query: str
    citations: Iterable[Citation]
    degradations: Iterable[RetrievalDegradation]

    def __post_init__(self) -> None:
        if not isinstance(self.reason, RefusalReason):
            raise TypeError("reason must be a RefusalReason")
        _require_non_empty(self.message, "message")
        _require_non_empty(self.original_query, "original_query")
        try:
            citations = tuple(self.citations)
            degradations = tuple(self.degradations)
        except TypeError as error:
            raise TypeError("citations and degradations must be iterable") from error
        if not all(isinstance(citation, Citation) for citation in citations):
            raise TypeError("citations must contain Citation values")
        if not all(isinstance(item, RetrievalDegradation) for item in degradations):
            raise TypeError("degradations must contain RetrievalDegradation values")
        object.__setattr__(self, "citations", citations)
        object.__setattr__(self, "degradations", degradations)
