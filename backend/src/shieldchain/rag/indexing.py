from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from shieldchain.rag.domain import IndexRecord, IndexStatus, KnowledgeChunk
from shieldchain.rag.ports import EmbeddingPort


class IndexingOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    ALREADY_SUCCEEDED = "already_succeeded"
    DELETED = "deleted"


@dataclass(frozen=True, slots=True)
class IndexingContext:
    """Server-resolved indexing authority; never accepted by the public service methods."""

    tenant_id: UUID
    knowledge_base_id: UUID
    document_id: UUID
    document_version_id: UUID
    published: bool
    cleanup_pending: bool = False

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "knowledge_base_id",
            "document_id",
            "document_version_id",
        ):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if not isinstance(self.published, bool) or not isinstance(self.cleanup_pending, bool):
            raise TypeError("published and cleanup_pending must be bool values")


@dataclass(frozen=True, slots=True)
class IndexingResult:
    outcome: IndexingOutcome
    document_version_id: UUID
    record_count: int


class IndexingOperationError(RuntimeError):
    def __init__(self, category: str, *, cleanup_pending: bool) -> None:
        super().__init__(f"indexing operation failed: {category}")
        self.category = category
        self.cleanup_pending = cleanup_pending


class IndexingRepository(Protocol):
    def resolve_indexing_context(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> IndexingContext | None: ...

    def list_chunks(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> Sequence[KnowledgeChunk]: ...

    def list_index_records(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> Sequence[IndexRecord]: ...

    def save_index_records(self, records: Sequence[IndexRecord], *, tenant_id: UUID) -> None: ...

    def delete_index_records(self, document_version_id: UUID, *, tenant_id: UUID) -> None: ...


class IndexLifecycle(Protocol):
    def mark_processing(self, context: IndexingContext, *, index_version: str) -> None: ...

    def mark_succeeded(self, context: IndexingContext, *, index_version: str) -> None: ...

    def mark_failed(
        self, context: IndexingContext, *, category: str, cleanup_pending: bool
    ) -> None: ...

    def mark_delete_pending(self, context: IndexingContext) -> None: ...

    def mark_deleted(self, context: IndexingContext) -> None: ...


class ContextualVectorIndex(Protocol):
    def upsert(
        self,
        chunks: Sequence[KnowledgeChunk],
        vectors: Sequence[Sequence[float]],
        *,
        context: IndexingContext,
    ) -> Sequence[IndexRecord]: ...

    def delete_document_version(self, *, context: IndexingContext) -> None: ...


class ContextualBm25Index(Protocol):
    def upsert(
        self, chunks: Sequence[KnowledgeChunk], *, context: IndexingContext
    ) -> Sequence[IndexRecord]: ...

    def delete_document_version(self, *, context: IndexingContext) -> None: ...


class IndexingService:
    """Coordinates both indexes with compensating cleanup and fail-closed authority."""

    def __init__(
        self,
        *,
        repository: IndexingRepository,
        lifecycle: IndexLifecycle,
        embedding: EmbeddingPort,
        vector_index: ContextualVectorIndex,
        bm25_index: ContextualBm25Index,
        embedding_model: str,
        index_version: str,
    ) -> None:
        if not embedding_model.strip() or not index_version.strip():
            raise ValueError("embedding_model and index_version must not be empty")
        self._repository = repository
        self._lifecycle = lifecycle
        self._embedding = embedding
        self._vector = vector_index
        self._bm25 = bm25_index
        self._embedding_model = embedding_model
        self._index_version = index_version

    def index(self, document_version_id: UUID, *, tenant_id: UUID) -> IndexingResult:
        context = self._resolve(document_version_id, tenant_id)
        chunks = tuple(
            self._repository.list_chunks(document_version_id, tenant_id=context.tenant_id)
        )
        if not chunks or any(chunk.document_version_id != document_version_id for chunk in chunks):
            raise ValueError("the server-resolved version has no valid chunks")

        records = tuple(
            self._repository.list_index_records(
                document_version_id, tenant_id=context.tenant_id
            )
        )
        if context.cleanup_pending:
            self._require_cleanup(context, category="retry_cleanup_failed")
            self._repository.delete_index_records(
                document_version_id, tenant_id=context.tenant_id
            )
            records = ()
        if self._is_complete(records, chunks):
            return IndexingResult(
                IndexingOutcome.ALREADY_SUCCEEDED, document_version_id, len(records)
            )

        self._lifecycle.mark_processing(context, index_version=self._index_version)
        try:
            vectors = tuple(
                tuple(vector)
                for vector in self._embedding.embed(
                    [chunk.text for chunk in chunks], model=self._embedding_model
                )
            )
            if len(vectors) != len(chunks):
                raise ValueError("embedding count mismatch")
        except Exception as error:
            self._lifecycle.mark_failed(
                context, category="embedding_failed", cleanup_pending=False
            )
            raise IndexingOperationError(
                "embedding_failed", cleanup_pending=False
            ) from error

        try:
            vector_records = tuple(self._vector.upsert(chunks, vectors, context=context))
            bm25_records = tuple(self._bm25.upsert(chunks, context=context))
            self._validate_adapter_records(vector_records, chunks, kind="vector")
            self._validate_adapter_records(bm25_records, chunks, kind="bm25")
            combined = self._combine_records(vector_records, bm25_records)
            self._repository.save_index_records(combined, tenant_id=context.tenant_id)
        except Exception as error:
            cleanup_pending = not self._cleanup(context)
            if not cleanup_pending:
                self._repository.delete_index_records(
                    document_version_id, tenant_id=context.tenant_id
                )
            self._lifecycle.mark_failed(
                context, category="index_write_failed", cleanup_pending=cleanup_pending
            )
            raise IndexingOperationError(
                "index_write_failed", cleanup_pending=cleanup_pending
            ) from error

        try:
            self._lifecycle.mark_succeeded(context, index_version=self._index_version)
        except Exception as error:
            cleanup_pending = not self._cleanup(context)
            if not cleanup_pending:
                self._repository.delete_index_records(
                    document_version_id, tenant_id=context.tenant_id
                )
            self._lifecycle.mark_failed(
                context, category="commit_failed", cleanup_pending=cleanup_pending
            )
            raise IndexingOperationError(
                "commit_failed", cleanup_pending=cleanup_pending
            ) from error
        return IndexingResult(IndexingOutcome.SUCCEEDED, document_version_id, len(combined))

    def rebuild(self, document_version_id: UUID, *, tenant_id: UUID) -> IndexingResult:
        context = self._resolve(document_version_id, tenant_id)
        self._require_cleanup(context, category="rebuild_cleanup_failed")
        self._repository.delete_index_records(
            document_version_id, tenant_id=context.tenant_id
        )
        return self.index(document_version_id, tenant_id=context.tenant_id)

    def sync_publication(
        self,
        active_version_id: UUID,
        *,
        superseded_version_ids: Sequence[UUID] = (),
        tenant_id: UUID,
    ) -> tuple[IndexingResult, ...]:
        """Refresh server-resolved publication flags after publish or rollback."""
        ordered = dict.fromkeys((active_version_id, *superseded_version_ids))
        return tuple(self.rebuild(version_id, tenant_id=tenant_id) for version_id in ordered)

    def delete(self, document_version_id: UUID, *, tenant_id: UUID) -> IndexingResult:
        context = self._resolve(document_version_id, tenant_id)
        self._lifecycle.mark_delete_pending(context)
        if not self._cleanup(context):
            self._lifecycle.mark_failed(
                context, category="index_delete_failed", cleanup_pending=True
            )
            raise IndexingOperationError("index_delete_failed", cleanup_pending=True)
        self._repository.delete_index_records(
            document_version_id, tenant_id=context.tenant_id
        )
        self._lifecycle.mark_deleted(context)
        return IndexingResult(IndexingOutcome.DELETED, document_version_id, 0)

    def _resolve(self, document_version_id: UUID, tenant_id: UUID) -> IndexingContext:
        if not isinstance(document_version_id, UUID) or not isinstance(tenant_id, UUID):
            raise TypeError("document_version_id and tenant_id must be UUID values")
        context = self._repository.resolve_indexing_context(
            document_version_id, tenant_id=tenant_id
        )
        if (
            context is None
            or context.tenant_id != tenant_id
            or context.document_version_id != document_version_id
        ):
            raise PermissionError("document version is not visible to this tenant")
        return context

    def _cleanup(self, context: IndexingContext) -> bool:
        succeeded = True
        for index in (self._vector, self._bm25):
            try:
                index.delete_document_version(context=context)
            except Exception:
                succeeded = False
        return succeeded

    def _require_cleanup(self, context: IndexingContext, *, category: str) -> None:
        if self._cleanup(context):
            return
        self._lifecycle.mark_failed(context, category=category, cleanup_pending=True)
        raise IndexingOperationError(category, cleanup_pending=True)

    def _is_complete(
        self, records: Sequence[IndexRecord], chunks: Sequence[KnowledgeChunk]
    ) -> bool:
        expected = {chunk.id for chunk in chunks}
        current = [record for record in records if record.index_version == self._index_version]
        return (
            len(current) == len(expected)
            and {record.chunk_id for record in current} == expected
            and all(
                record.status is IndexStatus.SUCCEEDED
                and record.vector_id is not None
                and record.bm25_key is not None
                and record.embedding_model == self._embedding_model
                for record in current
            )
        )

    def _validate_adapter_records(
        self,
        records: Sequence[IndexRecord],
        chunks: Sequence[KnowledgeChunk],
        *,
        kind: str,
    ) -> None:
        expected = {chunk.id for chunk in chunks}
        if len(records) != len(expected) or any(
            record.document_version_id != chunks[0].document_version_id
            or record.chunk_id not in expected
            or record.index_version != self._index_version
            or record.status is not IndexStatus.SUCCEEDED
            or (kind == "vector" and (record.vector_id is None or record.bm25_key is not None))
            or (kind == "bm25" and (record.bm25_key is None or record.vector_id is not None))
            for record in records
        ):
            raise ValueError("index adapter returned invalid records")
        if len({record.chunk_id for record in records}) != len(expected):
            raise ValueError("index adapter returned duplicate chunk records")

    def _combine_records(
        self,
        vector_records: Sequence[IndexRecord],
        bm25_records: Sequence[IndexRecord],
    ) -> tuple[IndexRecord, ...]:
        bm25_by_chunk = {record.chunk_id: record for record in bm25_records}
        return tuple(
            IndexRecord(
                id=vector_record.id,
                document_version_id=vector_record.document_version_id,
                chunk_id=vector_record.chunk_id,
                bm25_key=bm25_by_chunk[vector_record.chunk_id].bm25_key,
                embedding_model=vector_record.embedding_model,
                vector_id=vector_record.vector_id,
                reranker_model=vector_record.reranker_model,
                index_version=self._index_version,
                status=IndexStatus.SUCCEEDED,
                error_category=None,
                updated_at=datetime.now(UTC),
            )
            for vector_record in vector_records
        )
