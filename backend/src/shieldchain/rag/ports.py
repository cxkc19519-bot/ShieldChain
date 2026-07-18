from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import UUID

from shieldchain.rag.domain import (
    AccessScope,
    Citation,
    DocumentVersion,
    IndexRecord,
    KnowledgeBase,
    KnowledgeChunk,
    KnowledgeDocument,
)


class RagPortError(Exception):
    """Base error for a bounded RAG adapter failure."""


class ContentStoreError(RagPortError):
    pass


class ContentNotFoundError(ContentStoreError):
    pass


class ContentStoreUnavailableError(ContentStoreError):
    pass


class ParserError(RagPortError):
    pass


class ParserUnavailableError(ParserError):
    pass


class UnsupportedDocumentError(ParserError):
    pass


class ChunkOptimizationError(RagPortError):
    pass


class ChunkOptimizationUnavailableError(ChunkOptimizationError):
    pass


class ChunkOptimizationResponseError(ChunkOptimizationError):
    pass


class EmbeddingError(RagPortError):
    pass


class EmbeddingAuthenticationError(EmbeddingError):
    pass


class EmbeddingRateLimitError(EmbeddingError):
    pass


class EmbeddingUnavailableError(EmbeddingError):
    pass


class EmbeddingResponseError(EmbeddingError):
    pass


class VectorIndexError(RagPortError):
    pass


class VectorIndexUnavailableError(VectorIndexError):
    pass


class VectorIndexResponseError(VectorIndexError):
    pass


class Bm25IndexError(RagPortError):
    pass


class RerankerError(RagPortError):
    pass


class RerankerAuthenticationError(RerankerError):
    pass


class RerankerRateLimitError(RerankerError):
    pass


class RerankerUnavailableError(RerankerError):
    pass


class RerankerResponseError(RerankerError):
    pass


class KnowledgeRepositoryError(RagPortError):
    pass


class KnowledgeBaseNotFoundError(KnowledgeRepositoryError):
    pass


class KnowledgeDocumentNotFoundError(KnowledgeRepositoryError):
    pass


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _require_uuid(value: UUID, field_name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{field_name} must be a UUID")


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_sha256(value: str, field_name: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hexadecimal characters")


def _require_positive_int(value: int, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")


def _require_finite_score(
    value: float, field_name: str, *, minimum: float | None = None, maximum: float | None = None
) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{field_name} must be a finite score")
    if minimum is not None and value < minimum:
        raise ValueError(f"{field_name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{field_name} must be at most {maximum}")


@dataclass(frozen=True, slots=True)
class StoredContent:
    storage_key: str
    content_sha256: str
    size_bytes: int
    media_type: str

    def __post_init__(self) -> None:
        _require_non_empty(self.storage_key, "storage_key")
        _require_sha256(self.content_sha256, "content_sha256")
        _require_positive_int(self.size_bytes, "size_bytes")
        _require_non_empty(self.media_type, "media_type")


@dataclass(frozen=True, slots=True)
class ParsedContent:
    text: str
    media_type: str
    metadata: Mapping[str, str | int]

    def __post_init__(self) -> None:
        _require_non_empty(self.text, "text")
        _require_non_empty(self.media_type, "media_type")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        copied_metadata = dict(self.metadata)
        for key, value in copied_metadata.items():
            _require_non_empty(key, "metadata keys")
            if not isinstance(value, str | int):
                raise TypeError("metadata values must be strings or integers")
        object.__setattr__(self, "metadata", MappingProxyType(copied_metadata))


@dataclass(frozen=True, slots=True)
class ChunkBoundary:
    start: int
    end: int

    def __post_init__(self) -> None:
        if not isinstance(self.start, int) or isinstance(self.start, bool) or self.start < 0:
            raise ValueError("start must be a non-negative integer")
        _require_positive_int(self.end, "end")
        if self.start >= self.end:
            raise ValueError("start must be less than end")


@dataclass(frozen=True, slots=True)
class VectorMatch:
    chunk_id: UUID
    score: float

    def __post_init__(self) -> None:
        _require_uuid(self.chunk_id, "chunk_id")
        _require_finite_score(self.score, "score", minimum=0.0, maximum=1.0)


@dataclass(frozen=True, slots=True)
class Bm25Match:
    chunk_id: UUID
    score: float

    def __post_init__(self) -> None:
        _require_uuid(self.chunk_id, "chunk_id")
        _require_finite_score(self.score, "score", minimum=0.0)


@dataclass(frozen=True, slots=True)
class RerankedMatch:
    chunk_id: UUID
    score: float

    def __post_init__(self) -> None:
        _require_uuid(self.chunk_id, "chunk_id")
        _require_finite_score(self.score, "score", minimum=0.0, maximum=1.0)


@runtime_checkable
class ContentStorePort(Protocol):
    def put(self, content: Iterable[bytes], *, media_type: str) -> StoredContent: ...

    def read(self, storage_key: str) -> bytes: ...

    def delete(self, storage_key: str) -> None: ...


@runtime_checkable
class DocumentParserPort(Protocol):
    def parse(self, content: bytes, *, media_type: str, filename: str) -> ParsedContent: ...


@runtime_checkable
class ChunkBoundaryOptimizer(Protocol):
    def optimize(
        self,
        text: str,
        candidates: Sequence[ChunkBoundary],
        *,
        document_version_id: UUID,
    ) -> Sequence[ChunkBoundary]: ...


@runtime_checkable
class EmbeddingPort(Protocol):
    def embed(self, texts: Sequence[str], *, model: str) -> Sequence[Sequence[float]]: ...


@runtime_checkable
class VectorIndexPort(Protocol):
    def upsert(
        self,
        chunks: Sequence[KnowledgeChunk],
        vectors: Sequence[Sequence[float]],
        *,
        tenant_id: UUID,
        knowledge_base_id: UUID,
        document_id: UUID,
        document_version_id: UUID,
    ) -> Sequence[IndexRecord]: ...

    def search(
        self, vector: Sequence[float], *, scope: AccessScope, limit: int
    ) -> Sequence[VectorMatch]: ...

    def delete_document_version(self, document_version_id: UUID) -> None: ...


@runtime_checkable
class Bm25IndexPort(Protocol):
    def upsert(self, chunks: Sequence[KnowledgeChunk]) -> Sequence[IndexRecord]: ...

    def search(self, query: str, *, scope: AccessScope, limit: int) -> Sequence[Bm25Match]: ...

    def delete_document_version(self, document_version_id: UUID) -> None: ...


@runtime_checkable
class RerankerPort(Protocol):
    def rerank(
        self, query: str, chunks: Sequence[KnowledgeChunk], *, model: str
    ) -> Sequence[RerankedMatch]: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime: ...


@runtime_checkable
class KnowledgeRepository(Protocol):
    def get_knowledge_base(
        self, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeBase | None: ...

    def get_document(self, document_id: UUID, *, tenant_id: UUID) -> KnowledgeDocument | None: ...

    def get_version(self, version_id: UUID, *, tenant_id: UUID) -> DocumentVersion | None: ...

    def list_chunks(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> Sequence[KnowledgeChunk]: ...

    def save_index_records(self, records: Sequence[IndexRecord], *, tenant_id: UUID) -> None: ...

    def list_citations(
        self, chunk_ids: Sequence[UUID], *, scope: AccessScope
    ) -> Sequence[Citation]: ...


def index_metadata_for_chunk(
    chunk: KnowledgeChunk,
    *,
    tenant_id: UUID,
    knowledge_base_id: UUID,
    document_id: UUID,
    published: bool,
) -> Mapping[str, object]:
    """Build the mandatory provider filter metadata without widening its ACL."""
    _require_uuid(tenant_id, "tenant_id")
    _require_uuid(knowledge_base_id, "knowledge_base_id")
    _require_uuid(document_id, "document_id")
    if not isinstance(published, bool):
        raise TypeError("published must be a bool")
    return MappingProxyType({
        "tenant_id": tenant_id,
        "knowledge_base_id": knowledge_base_id,
        "document_id": document_id,
        "document_version_id": chunk.document_version_id,
        "sensitivity": chunk.sensitivity.value,
        "permission_tags": tuple(sorted(chunk.permission_tags)),
        "published": published,
    })
