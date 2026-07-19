"""Tenant-bound SQLAlchemy repository for the RAG control plane."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from shieldchain.rag.chunking import ChunkedItem, ChunkingResult
from shieldchain.rag.domain import (
    AccessScope,
    ChunkingStatus,
    ChunkSource,
    Citation,
    DocumentStatus,
    DocumentVersion,
    IndexRecord,
    IndexStatus,
    KnowledgeBase,
    KnowledgeBaseStatus,
    KnowledgeChunk,
    KnowledgeDocument,
    ParsingStatus,
    SensitivityLevel,
)
from shieldchain.rag.indexing import IndexingContext
from shieldchain.rag.persistence import (
    ChunkSourceRow,
    DocumentVersionRow,
    KnowledgeBaseRow,
    KnowledgeChunkRow,
    KnowledgeDocumentRow,
    RagIndexRecordRow,
)
from shieldchain.rag.retrieval import TrustedChunkMetadata
from shieldchain.rag.semantic_chunking import (
    SemanticBoundaryValidationError,
    SemanticChunkingResult,
    build_semantic_items,
    semantic_retry_key,
    validate_rule_chunking_result,
)


class InvalidDocumentLifecycle(ValueError):
    """Raised when a tenant-bound document state change is invalid."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require_lifecycle_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("lifecycle now must be an aware UTC datetime")
    return value.astimezone(UTC)


def _knowledge_base_from_row(row: KnowledgeBaseRow) -> KnowledgeBase:
    return KnowledgeBase(
        id=UUID(row.id),
        tenant_id=UUID(row.tenant_id),
        name=row.name,
        status=KnowledgeBaseStatus(row.status),
        default_sensitivity=SensitivityLevel(row.default_sensitivity),
        version_policy=row.version_policy,
        created_at=_utc(row.created_at),
        updated_at=_utc(row.updated_at),
    )


def _document_from_row(row: KnowledgeDocumentRow) -> KnowledgeDocument:
    return KnowledgeDocument(
        id=UUID(row.id),
        knowledge_base_id=UUID(row.knowledge_base_id),
        tenant_id=UUID(row.tenant_id),
        original_filename=row.original_filename,
        storage_key=row.storage_key,
        media_type=row.media_type,
        content_sha256=row.content_sha256,
        status=DocumentStatus(row.status),
        current_version_id=UUID(row.current_version_id) if row.current_version_id else None,
        created_at=_utc(row.created_at),
        updated_at=_utc(row.updated_at),
    )


def _version_from_row(row: DocumentVersionRow) -> DocumentVersion:
    return DocumentVersion(
        id=UUID(row.id),
        document_id=UUID(row.document_id),
        version_number=row.version_number,
        parsing_status=ParsingStatus(row.parsing_status),
        chunking_status=ChunkingStatus(row.chunking_status),
        index_status=IndexStatus(row.index_status),
        parser_name=row.parser_name,
        parser_version=row.parser_version,
        chunking_strategy=row.chunking_strategy,
        chunking_prompt_version=row.chunking_prompt_version,
        chunking_model=row.chunking_model,
        created_at=_utc(row.created_at),
        published_at=_utc(row.published_at) if row.published_at else None,
        chunking_failure_category=row.chunking_failure_category,
        chunking_retry_key=row.chunking_retry_key,
        chunking_requested_model=row.chunking_requested_model,
    )


_SOURCE_NAMESPACE = UUID("6f9d9e3a-3f4b-568b-9ad7-91b11f3d9454")


def _chunk_from_row(
    row: KnowledgeChunkRow, sources: Sequence[ChunkSourceRow] = ()
) -> KnowledgeChunk:
    return KnowledgeChunk(
        id=UUID(row.id),
        document_version_id=UUID(row.document_version_id),
        ordinal=row.ordinal,
        heading_path=tuple(row.heading_path_json),
        page_number=row.page_number,
        structural_location=row.structural_location,
        text=row.text,
        token_count=row.token_count,
        content_sha256=row.content_sha256,
        sensitivity=SensitivityLevel(row.sensitivity),
        permission_tags=frozenset(row.permission_tags_json),
        chunking_mode=row.chunking_mode,
        is_degraded=row.is_degraded,
        sources=tuple(
            ChunkSource(
                chunk_id=UUID(source.chunk_id),
                occurrence_ordinal=source.occurrence_ordinal,
                parsed_element_ordinal=source.parsed_element_ordinal,
                start_offset=source.start_offset,
                end_offset=source.end_offset,
                heading_path=tuple(source.heading_path_json),
                page_number=source.page_number,
                structural_location=source.structural_location,
            )
            for source in sorted(sources, key=lambda item: item.occurrence_ordinal)
        ),
    )


def _index_from_row(row: RagIndexRecordRow) -> IndexRecord:
    return IndexRecord(
        id=UUID(row.id),
        document_version_id=UUID(row.document_version_id),
        chunk_id=UUID(row.chunk_id),
        bm25_key=row.bm25_key,
        embedding_model=row.embedding_model,
        vector_id=row.vector_id,
        reranker_model=row.reranker_model,
        index_version=row.index_version,
        status=IndexStatus(row.status),
        error_category=row.error_category,
        updated_at=_utc(row.updated_at),
    )


class SqlAlchemyKnowledgeRepository:
    """Explicitly scopes every RAG lookup by the server-selected tenant identifier."""

    def create_knowledge_base(
        self, session: Session, knowledge_base: KnowledgeBase
    ) -> KnowledgeBase:
        existing = session.execute(
            select(KnowledgeBaseRow).where(KnowledgeBaseRow.id == str(knowledge_base.id))
        ).scalar_one_or_none()
        if existing is not None:
            if existing.tenant_id != str(knowledge_base.tenant_id):
                raise InvalidDocumentLifecycle("knowledge base id belongs to another tenant")
            return _knowledge_base_from_row(existing)
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            session.add(
                KnowledgeBaseRow(
                    id=str(knowledge_base.id),
                    tenant_id=str(knowledge_base.tenant_id),
                    name=knowledge_base.name,
                    status=knowledge_base.status.value,
                    default_sensitivity=knowledge_base.default_sensitivity.value,
                    version_policy=knowledge_base.version_policy,
                    created_at=knowledge_base.created_at,
                    updated_at=knowledge_base.updated_at,
                )
            )
            session.flush()
        return knowledge_base

    def create_document(self, session: Session, document: KnowledgeDocument) -> KnowledgeDocument:
        base = session.execute(
            select(KnowledgeBaseRow)
            .where(
                KnowledgeBaseRow.id == str(document.knowledge_base_id),
                KnowledgeBaseRow.tenant_id == str(document.tenant_id),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if base is None:
            raise InvalidDocumentLifecycle("knowledge base is not visible to this tenant")
        existing = session.execute(
            select(KnowledgeDocumentRow).where(
                KnowledgeDocumentRow.knowledge_base_id == str(document.knowledge_base_id),
                KnowledgeDocumentRow.content_sha256 == document.content_sha256,
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.tenant_id != str(document.tenant_id):
                raise InvalidDocumentLifecycle("content belongs to another tenant")
            return _document_from_row(existing)
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            session.add(
                KnowledgeDocumentRow(
                    id=str(document.id),
                    knowledge_base_id=str(document.knowledge_base_id),
                    tenant_id=str(document.tenant_id),
                    original_filename=document.original_filename,
                    storage_key=document.storage_key,
                    media_type=document.media_type,
                    content_sha256=document.content_sha256,
                    status=document.status.value,
                    current_version_id=str(document.current_version_id)
                    if document.current_version_id
                    else None,
                    created_at=document.created_at,
                    updated_at=document.updated_at,
                )
            )
            session.flush()
        return document

    def create_version(
        self,
        session: Session,
        version: DocumentVersion,
        chunks: Sequence[KnowledgeChunk],
        *,
        tenant_id: UUID,
        idempotency_key: str,
    ) -> DocumentVersion:
        if not idempotency_key.strip():
            raise ValueError("idempotency_key must not be empty")
        document = self._require_document(session, version.document_id, tenant_id, lock=True)
        existing = session.execute(
            select(DocumentVersionRow).where(
                DocumentVersionRow.document_id == document.id,
                DocumentVersionRow.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return _version_from_row(existing)
        if not chunks or any(
            chunk.document_version_id != version.id or not chunk.sources for chunk in chunks
        ):
            raise InvalidDocumentLifecycle("a version must persist its own non-empty chunks")
        degraded_fallback = all(
            chunk.chunking_mode == "rule_degraded" and chunk.is_degraded for chunk in chunks
        )
        contains_degraded_fallback = any(
            chunk.chunking_mode == "rule_degraded" for chunk in chunks
        )
        if version.chunking_failure_category is not None and not degraded_fallback:
            raise InvalidDocumentLifecycle("chunking failure audit requires degraded rule chunks")
        if contains_degraded_fallback and (
            not degraded_fallback
            or version.chunking_failure_category is None
            or version.chunking_retry_key is None
            or version.chunking_prompt_version is None
            or version.chunking_model is None
            or version.chunking_requested_model is None
        ):
            raise InvalidDocumentLifecycle("degraded rule chunks require complete retry audit")
        if contains_degraded_fallback:
            if version.chunking_model != version.chunking_requested_model:
                raise InvalidDocumentLifecycle(
                    "degraded rule chunks must record the requested model consistently"
                )
            expected_retry_key = semantic_retry_key(
                chunks,
                version.id,
                strategy_version=version.chunking_strategy,
                prompt_version=version.chunking_prompt_version or "",
                requested_model=version.chunking_requested_model or "",
            )
            if version.chunking_retry_key != expected_retry_key:
                raise InvalidDocumentLifecycle("degraded rule chunk retry key is invalid")
        contains_semantic = any(chunk.chunking_mode == "semantic" for chunk in chunks)
        if contains_semantic:
            raise InvalidDocumentLifecycle(
                "semantic chunks require create_version_from_semantic_result"
            )
        return self._insert_version_rows(session, version, chunks, idempotency_key)

    def create_version_from_semantic_result(
        self,
        session: Session,
        version: DocumentVersion,
        rule_result: ChunkingResult,
        result: SemanticChunkingResult,
        *,
        tenant_id: UUID,
        idempotency_key: str,
    ) -> DocumentVersion:
        if not idempotency_key.strip():
            raise ValueError("idempotency_key must not be empty")
        chunks = tuple(item.chunk for item in result.items)
        audit = result.audit
        try:
            validate_rule_chunking_result(rule_result, version.id)
        except ValueError as error:
            raise InvalidDocumentLifecycle("semantic create rule input is invalid") from error
        if (
            not chunks
            or audit.outcome != "semantic"
            or audit.failure_category is not None
            or audit.document_version_id != version.id
            or any(chunk.document_version_id != version.id for chunk in chunks)
            or any(
                item.chunk.document_version_id != version.id for item in rule_result.items
            )
        ):
            raise InvalidDocumentLifecycle("semantic create result is invalid")
        expected_retry_key = semantic_retry_key(
            rule_result.items,
            version.id,
            strategy_version=audit.strategy_version,
            prompt_version=audit.prompt_version,
            requested_model=audit.requested_model,
        )
        try:
            expected_items = build_semantic_items(
                rule_result.items, result.boundaries, document_version_id=version.id
            )
        except SemanticBoundaryValidationError as error:
            raise InvalidDocumentLifecycle("semantic create boundaries are invalid") from error
        actual_model = audit.response_model or audit.requested_model
        if (
            expected_items != result.items
            or result.retry_key != expected_retry_key
            or version.chunking_retry_key != expected_retry_key
            or version.chunking_strategy != audit.strategy_version
            or version.chunking_prompt_version != audit.prompt_version
            or version.chunking_requested_model != audit.requested_model
            or version.chunking_model != actual_model
            or version.chunking_failure_category is not None
        ):
            raise InvalidDocumentLifecycle(
                "semantic create audit does not match deterministic input"
            )
        document = self._require_document(session, version.document_id, tenant_id, lock=True)
        if document.status in {DocumentStatus.DELETE_PENDING.value, DocumentStatus.DELETED.value}:
            raise InvalidDocumentLifecycle("deleting documents cannot create semantic versions")
        if (
            version.parsing_status is not ParsingStatus.SUCCEEDED
            or version.chunking_status is not ChunkingStatus.SUCCEEDED
            or version.index_status not in {IndexStatus.PENDING, IndexStatus.FAILED}
        ):
            raise InvalidDocumentLifecycle(
                "semantic create requires completed parsing/chunking and an inactive index"
            )
        existing = session.execute(
            select(DocumentVersionRow).where(
                DocumentVersionRow.document_id == document.id,
                DocumentVersionRow.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return _version_from_row(existing)
        return self._insert_version_rows(session, version, chunks, idempotency_key)

    def _insert_version_rows(
        self,
        session: Session,
        version: DocumentVersion,
        chunks: Sequence[KnowledgeChunk],
        idempotency_key: str,
    ) -> DocumentVersion:
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            session.add(
                DocumentVersionRow(
                    id=str(version.id),
                    document_id=str(version.document_id),
                    version_number=version.version_number,
                    idempotency_key=idempotency_key,
                    parsing_status=version.parsing_status.value,
                    chunking_status=version.chunking_status.value,
                    index_status=version.index_status.value,
                    parser_name=version.parser_name,
                    parser_version=version.parser_version,
                    chunking_strategy=version.chunking_strategy,
                    chunking_prompt_version=version.chunking_prompt_version,
                    chunking_model=version.chunking_model,
                    chunking_failure_category=version.chunking_failure_category,
                    chunking_retry_key=version.chunking_retry_key,
                    chunking_requested_model=version.chunking_requested_model,
                    created_at=version.created_at,
                    published_at=version.published_at,
                )
            )
            self._add_chunks(session, chunks)
            session.flush()
        return version

    def upgrade_semantic_chunking(
        self,
        session: Session,
        result: SemanticChunkingResult,
        *,
        tenant_id: UUID,
    ) -> DocumentVersion:
        """Atomically replace persisted rule fallback chunks with a verified semantic retry."""
        audit = result.audit
        chunks = tuple(item.chunk for item in result.items)
        if (
            not chunks
            or audit.outcome != "semantic"
            or audit.failure_category is not None
            or audit.document_version_id != chunks[0].document_version_id
        ):
            raise InvalidDocumentLifecycle("only a successful semantic result can upgrade chunks")
        if any(
            chunk.document_version_id != audit.document_version_id
            or not chunk.sources
            or chunk.chunking_mode != "semantic"
            or item.sources != chunk.sources
            for item, chunk in zip(result.items, chunks, strict=True)
        ):
            raise InvalidDocumentLifecycle("semantic retry chunks are invalid")
        if [chunk.ordinal for chunk in chunks] != list(range(len(chunks))):
            raise InvalidDocumentLifecycle("semantic retry chunk ordinals must be contiguous")
        if len({chunk.id for chunk in chunks}) != len(chunks):
            raise InvalidDocumentLifecycle("semantic retry chunk ids must be unique")

        document = session.execute(
            self._document_for_version_lock_statement(audit.document_version_id, tenant_id)
        ).scalar_one_or_none()
        if document is None:
            raise InvalidDocumentLifecycle("version is not visible to this tenant")
        version = self._require_version(
            session, audit.document_version_id, tenant_id, lock=True
        )
        if document.status in {DocumentStatus.DELETE_PENDING.value, DocumentStatus.DELETED.value}:
            raise InvalidDocumentLifecycle("deleting documents cannot be semantically upgraded")
        if version.index_status in {IndexStatus.DELETE_PENDING.value, IndexStatus.DELETED.value}:
            raise InvalidDocumentLifecycle("deleting versions cannot be semantically upgraded")
        if (
            version.parsing_status != ParsingStatus.SUCCEEDED.value
            or version.chunking_status != ChunkingStatus.SUCCEEDED.value
            or version.index_status not in {IndexStatus.PENDING.value, IndexStatus.FAILED.value}
        ):
            raise InvalidDocumentLifecycle(
                "semantic upgrade requires completed parsing/chunking and an inactive index"
            )
        if version.chunking_retry_key != result.retry_key:
            raise InvalidDocumentLifecycle("semantic retry key does not match the version")
        current_chunks = tuple(
            self.list_chunks(session, audit.document_version_id, tenant_id=tenant_id)
        )
        audit_matches = (
            version.chunking_strategy == audit.strategy_version
            and version.chunking_prompt_version == audit.prompt_version
            and version.chunking_requested_model == audit.requested_model
            and version.chunking_model == (audit.response_model or audit.requested_model)
        )
        if version.chunking_failure_category is None:
            if current_chunks == chunks and audit_matches:
                return _version_from_row(version)
            raise InvalidDocumentLifecycle("completed semantic chunks cannot be replaced")
        if (
            version.chunking_strategy != audit.strategy_version
            or version.chunking_prompt_version != audit.prompt_version
            or version.chunking_requested_model != audit.requested_model
        ):
            raise InvalidDocumentLifecycle("semantic retry audit does not match persisted intent")
        expected_retry_key = semantic_retry_key(
            current_chunks,
            audit.document_version_id,
            strategy_version=version.chunking_strategy,
            prompt_version=version.chunking_prompt_version,
            requested_model=version.chunking_requested_model,
        )
        if version.chunking_retry_key != expected_retry_key:
            raise InvalidDocumentLifecycle("persisted semantic retry key is invalid")
        if not current_chunks or any(
            chunk.chunking_mode != "rule_degraded" or not chunk.is_degraded
            for chunk in current_chunks
        ):
            raise InvalidDocumentLifecycle("only persisted rule fallback chunks can be upgraded")
        expected_acl = {
            (chunk.sensitivity, chunk.permission_tags) for chunk in current_chunks
        }
        replacement_acl = {(chunk.sensitivity, chunk.permission_tags) for chunk in chunks}
        if len(expected_acl) != 1 or replacement_acl != expected_acl:
            raise InvalidDocumentLifecycle("semantic retry cannot change chunk ACL values")

        def provenance(chunk_values: Sequence[KnowledgeChunk]) -> Counter[tuple[object, ...]]:
            return Counter(
                (
                    source.parsed_element_ordinal,
                    source.start_offset,
                    source.end_offset,
                    source.heading_path,
                    source.page_number,
                    source.structural_location,
                )
                for chunk in chunk_values
                for source in chunk.sources
            )

        if provenance(chunks) != provenance(current_chunks):
            raise InvalidDocumentLifecycle("semantic retry cannot change source provenance")
        current_items = tuple(ChunkedItem(chunk, chunk.sources) for chunk in current_chunks)
        try:
            expected_items = build_semantic_items(
                current_items,
                result.boundaries,
                document_version_id=audit.document_version_id,
            )
        except SemanticBoundaryValidationError as error:
            raise InvalidDocumentLifecycle("semantic retry boundaries are invalid") from error
        if expected_items != result.items:
            raise InvalidDocumentLifecycle("semantic retry output does not match its boundaries")
        indexed = session.execute(
            select(RagIndexRecordRow.id)
            .where(RagIndexRecordRow.document_version_id == str(audit.document_version_id))
            .limit(1)
        ).scalar_one_or_none()
        if indexed is not None:
            raise InvalidDocumentLifecycle(
                "semantic upgrade requires external indexes to be removed first"
            )

        old_chunk_ids = [str(chunk.id) for chunk in current_chunks]
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            session.execute(
                delete(ChunkSourceRow).where(ChunkSourceRow.chunk_id.in_(old_chunk_ids))
            )
            session.execute(
                delete(KnowledgeChunkRow).where(
                    KnowledgeChunkRow.document_version_id == str(audit.document_version_id)
                )
            )
            self._add_chunks(session, chunks)
            version.chunking_strategy = audit.strategy_version
            version.chunking_prompt_version = audit.prompt_version
            version.chunking_model = audit.response_model or audit.requested_model
            version.chunking_failure_category = None
            version.index_status = IndexStatus.PENDING.value
            session.flush()
        return _version_from_row(version)

    @staticmethod
    def _document_for_version_lock_statement(version_id: UUID, tenant_id: UUID):
        return (
            select(KnowledgeDocumentRow)
            .join(DocumentVersionRow, DocumentVersionRow.document_id == KnowledgeDocumentRow.id)
            .where(
                DocumentVersionRow.id == str(version_id),
                KnowledgeDocumentRow.tenant_id == str(tenant_id),
            )
            .with_for_update(of=KnowledgeDocumentRow)
        )

    @staticmethod
    def _add_chunks(session: Session, chunks: Sequence[KnowledgeChunk]) -> None:
        session.add_all(
            [
                KnowledgeChunkRow(
                    id=str(chunk.id),
                    document_version_id=str(chunk.document_version_id),
                    ordinal=chunk.ordinal,
                    heading_path_json=list(chunk.heading_path),
                    page_number=chunk.page_number,
                    structural_location=chunk.structural_location,
                    text=chunk.text,
                    token_count=chunk.token_count,
                    content_sha256=chunk.content_sha256,
                    sensitivity=chunk.sensitivity.value,
                    permission_tags_json=sorted(chunk.permission_tags),
                    chunking_mode=chunk.chunking_mode,
                    is_degraded=chunk.is_degraded,
                )
                for chunk in chunks
            ]
        )
        session.add_all(
            [
                ChunkSourceRow(
                    id=str(
                        uuid5(_SOURCE_NAMESPACE, f"{source.chunk_id}:{source.occurrence_ordinal}")
                    ),
                    chunk_id=str(source.chunk_id),
                    occurrence_ordinal=source.occurrence_ordinal,
                    parsed_element_ordinal=source.parsed_element_ordinal,
                    start_offset=source.start_offset,
                    end_offset=source.end_offset,
                    heading_path_json=list(source.heading_path),
                    page_number=source.page_number,
                    structural_location=source.structural_location,
                )
                for chunk in chunks
                for source in chunk.sources
            ]
        )

    def get_knowledge_base(
        self, session: Session, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeBase | None:
        row = session.execute(
            select(KnowledgeBaseRow).where(
                KnowledgeBaseRow.id == str(knowledge_base_id),
                KnowledgeBaseRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        return _knowledge_base_from_row(row) if row else None

    def get_document(
        self, session: Session, document_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeDocument | None:
        row = session.execute(
            select(KnowledgeDocumentRow).where(
                KnowledgeDocumentRow.id == str(document_id),
                KnowledgeDocumentRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        return _document_from_row(row) if row else None

    def get_version(
        self, session: Session, version_id: UUID, *, tenant_id: UUID
    ) -> DocumentVersion | None:
        row = session.execute(
            select(DocumentVersionRow)
            .join(KnowledgeDocumentRow, DocumentVersionRow.document_id == KnowledgeDocumentRow.id)
            .where(
                DocumentVersionRow.id == str(version_id),
                KnowledgeDocumentRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        return _version_from_row(row) if row else None

    def list_chunks(
        self, session: Session, document_version_id: UUID, *, tenant_id: UUID
    ) -> Sequence[KnowledgeChunk]:
        rows = (
            session.execute(
                select(KnowledgeChunkRow)
                .join(DocumentVersionRow)
                .join(
                    KnowledgeDocumentRow, DocumentVersionRow.document_id == KnowledgeDocumentRow.id
                )
                .where(
                    KnowledgeChunkRow.document_version_id == str(document_version_id),
                    KnowledgeDocumentRow.tenant_id == str(tenant_id),
                )
                .order_by(KnowledgeChunkRow.ordinal)
            )
            .scalars()
            .all()
        )
        sources = (
            session.execute(
                select(ChunkSourceRow).where(ChunkSourceRow.chunk_id.in_([row.id for row in rows]))
            )
            .scalars()
            .all()
        )
        sources_by_chunk: dict[str, list[ChunkSourceRow]] = {}
        for source in sources:
            sources_by_chunk.setdefault(source.chunk_id, []).append(source)
        return tuple(_chunk_from_row(row, sources_by_chunk.get(row.id, ())) for row in rows)

    def save_index_records(
        self, session: Session, records: Sequence[IndexRecord], *, tenant_id: UUID
    ) -> None:
        if not records:
            return
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            for record in records:
                chunk = session.execute(
                    select(KnowledgeChunkRow)
                    .join(
                        DocumentVersionRow,
                        KnowledgeChunkRow.document_version_id == DocumentVersionRow.id,
                    )
                    .join(
                        KnowledgeDocumentRow,
                        DocumentVersionRow.document_id == KnowledgeDocumentRow.id,
                    )
                    .where(
                        KnowledgeChunkRow.id == str(record.chunk_id),
                        KnowledgeChunkRow.document_version_id == str(record.document_version_id),
                        KnowledgeDocumentRow.tenant_id == str(tenant_id),
                    )
                ).scalar_one_or_none()
                if chunk is None:
                    raise InvalidDocumentLifecycle(
                        "index record must reference a chunk in its version"
                    )
                existing = session.execute(
                    select(RagIndexRecordRow)
                    .join(
                        DocumentVersionRow,
                        RagIndexRecordRow.document_version_id == DocumentVersionRow.id,
                    )
                    .join(
                        KnowledgeDocumentRow,
                        DocumentVersionRow.document_id == KnowledgeDocumentRow.id,
                    )
                    .where(
                        RagIndexRecordRow.id == str(record.id),
                        KnowledgeDocumentRow.tenant_id == str(tenant_id),
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    if (
                        existing.chunk_id != str(record.chunk_id)
                        or existing.index_version != record.index_version
                    ):
                        raise InvalidDocumentLifecycle("index record id cannot be reassigned")
                    continue
                session.add(
                    RagIndexRecordRow(
                        id=str(record.id),
                        document_version_id=str(record.document_version_id),
                        chunk_id=str(record.chunk_id),
                        bm25_key=record.bm25_key,
                        embedding_model=record.embedding_model,
                        vector_id=record.vector_id,
                        reranker_model=record.reranker_model,
                        index_version=record.index_version,
                        status=record.status.value,
                        error_category=record.error_category,
                        updated_at=record.updated_at,
                    )
                )
            session.flush()

    def publish_version(
        self,
        session: Session,
        document_id: UUID,
        version_id: UUID,
        *,
        tenant_id: UUID,
        now: datetime,
    ) -> KnowledgeDocument:
        now = _require_lifecycle_utc(now)
        document = self._require_document(session, document_id, tenant_id, lock=True)
        version = self._require_version(session, version_id, tenant_id, lock=True)
        if version.document_id != document.id or document.status in {"delete_pending", "deleted"}:
            raise InvalidDocumentLifecycle("version cannot be published for this document")
        if (
            version.parsing_status != ParsingStatus.SUCCEEDED.value
            or version.chunking_status != ChunkingStatus.SUCCEEDED.value
            or version.index_status != IndexStatus.SUCCEEDED.value
        ):
            raise InvalidDocumentLifecycle(
                "only fully processed and indexed versions can be published"
            )
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            document.current_version_id = version.id
            document.status = DocumentStatus.PUBLISHED.value
            document.updated_at = _utc(now)
            version.published_at = _utc(now)
            session.flush()
        return _document_from_row(document)

    def rollback_to_version(
        self,
        session: Session,
        document_id: UUID,
        version_id: UUID,
        *,
        tenant_id: UUID,
        now: datetime,
    ) -> KnowledgeDocument:
        now = _require_lifecycle_utc(now)
        document = self._require_document(session, document_id, tenant_id, lock=True)
        version = self._require_version(session, version_id, tenant_id, lock=True)
        if (
            document.status != DocumentStatus.PUBLISHED.value
            or version.document_id != document.id
            or version.published_at is None
        ):
            raise InvalidDocumentLifecycle("rollback requires a published document and version")
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            document.current_version_id = version.id
            document.updated_at = now
            session.flush()
        return _document_from_row(document)

    def mark_delete_pending(
        self, session: Session, document_id: UUID, *, tenant_id: UUID, now: datetime
    ) -> KnowledgeDocument:
        now = _require_lifecycle_utc(now)
        document = self._require_document(session, document_id, tenant_id, lock=True)
        if document.status == DocumentStatus.DELETED.value:
            raise InvalidDocumentLifecycle("deleted documents cannot be scheduled again")
        self._ensure_sqlite_outer_transaction(session)
        with session.begin_nested():
            document.status = DocumentStatus.DELETE_PENDING.value
            document.updated_at = _utc(now)
            session.execute(
                update(DocumentVersionRow)
                .where(DocumentVersionRow.document_id == document.id)
                .values(index_status=IndexStatus.DELETE_PENDING.value)
            )
            session.execute(
                update(RagIndexRecordRow)
                .where(
                    RagIndexRecordRow.document_version_id.in_(
                        select(DocumentVersionRow.id).where(
                            DocumentVersionRow.document_id == document.id
                        )
                    )
                )
                .values(status=IndexStatus.DELETE_PENDING.value, updated_at=_utc(now))
            )
            session.flush()
        return _document_from_row(document)

    def list_citations(
        self, session: Session, chunk_ids: Sequence[UUID], *, scope: AccessScope
    ) -> Sequence[Citation]:
        if not chunk_ids:
            return ()
        rows = session.execute(
            select(KnowledgeChunkRow, DocumentVersionRow, KnowledgeDocumentRow)
            .join(
                DocumentVersionRow, KnowledgeChunkRow.document_version_id == DocumentVersionRow.id
            )
            .join(KnowledgeDocumentRow, DocumentVersionRow.document_id == KnowledgeDocumentRow.id)
            .join(KnowledgeBaseRow, KnowledgeDocumentRow.knowledge_base_id == KnowledgeBaseRow.id)
            .where(
                KnowledgeChunkRow.id.in_([str(value) for value in chunk_ids]),
                KnowledgeDocumentRow.tenant_id == str(scope.tenant_id),
                KnowledgeDocumentRow.status == DocumentStatus.PUBLISHED.value,
                KnowledgeDocumentRow.current_version_id == DocumentVersionRow.id,
                KnowledgeBaseRow.status == KnowledgeBaseStatus.PUBLISHED.value,
            )
        ).all()
        citations: list[Citation] = []
        for chunk, version, document in rows:
            if not scope.allows(
                UUID(document.tenant_id),
                UUID(document.knowledge_base_id),
                SensitivityLevel(chunk.sensitivity),
                chunk.permission_tags_json,
            ):
                continue
            citations.append(
                Citation(
                    knowledge_base_id=UUID(document.knowledge_base_id),
                    document_id=UUID(document.id),
                    document_version_id=UUID(version.id),
                    chunk_id=UUID(chunk.id),
                    heading_path=tuple(chunk.heading_path_json),
                    page_number=chunk.page_number,
                    structural_location=chunk.structural_location,
                    excerpt=chunk.text,
                    bm25_score=None,
                    vector_score=None,
                    fusion_score=0.0,
                    reranker_score=None,
                    updated_at=_utc(document.updated_at),
                    integrity_sha256=chunk.content_sha256,
                )
            )
        return tuple(citations)

    @staticmethod
    def _require_document(
        session: Session, document_id: UUID, tenant_id: UUID, *, lock: bool
    ) -> KnowledgeDocumentRow:
        statement = select(KnowledgeDocumentRow).where(
            KnowledgeDocumentRow.id == str(document_id),
            KnowledgeDocumentRow.tenant_id == str(tenant_id),
        )
        if lock:
            statement = statement.with_for_update()
        row = session.execute(statement).scalar_one_or_none()
        if row is None:
            raise InvalidDocumentLifecycle("document is not visible to this tenant")
        return row

    @staticmethod
    def _require_version(
        session: Session, version_id: UUID, tenant_id: UUID, *, lock: bool
    ) -> DocumentVersionRow:
        statement = (
            select(DocumentVersionRow)
            .join(KnowledgeDocumentRow, DocumentVersionRow.document_id == KnowledgeDocumentRow.id)
            .where(
                DocumentVersionRow.id == str(version_id),
                KnowledgeDocumentRow.tenant_id == str(tenant_id),
            )
        )
        if lock:
            statement = statement.with_for_update()
        row = session.execute(statement).scalar_one_or_none()
        if row is None:
            raise InvalidDocumentLifecycle("version is not visible to this tenant")
        return row

    @staticmethod
    def _ensure_sqlite_outer_transaction(session: Session) -> None:
        connection = session.connection()
        if connection.dialect.name != "sqlite":
            return
        driver_connection = connection.connection.driver_connection
        if not driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN")


class SqlAlchemyIndexingUnitOfWork:
    """Session-bound production adapter for the indexing service and lifecycle."""

    def __init__(
        self,
        session: Session,
        *,
        repository: SqlAlchemyKnowledgeRepository | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._session = session
        self._repository = repository or SqlAlchemyKnowledgeRepository()
        self._clock = clock or (lambda: datetime.now(UTC))

    def resolve_indexing_context(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> IndexingContext | None:
        row = self._session.execute(
            select(DocumentVersionRow, KnowledgeDocumentRow, KnowledgeBaseRow)
            .join(KnowledgeDocumentRow, DocumentVersionRow.document_id == KnowledgeDocumentRow.id)
            .join(KnowledgeBaseRow, KnowledgeDocumentRow.knowledge_base_id == KnowledgeBaseRow.id)
            .where(
                DocumentVersionRow.id == str(document_version_id),
                KnowledgeDocumentRow.tenant_id == str(tenant_id),
            )
        ).one_or_none()
        if row is None:
            return None
        version, document, base = row
        published = (
            document.status == DocumentStatus.PUBLISHED.value
            and document.current_version_id == version.id
            and base.status == KnowledgeBaseStatus.PUBLISHED.value
        )
        return IndexingContext(
            tenant_id=UUID(document.tenant_id),
            knowledge_base_id=UUID(document.knowledge_base_id),
            document_id=UUID(document.id),
            document_version_id=UUID(version.id),
            published=published,
            cleanup_pending=version.index_status == IndexStatus.DELETE_PENDING.value,
        )

    def list_chunks(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> Sequence[KnowledgeChunk]:
        return self._repository.list_chunks(
            self._session, document_version_id, tenant_id=tenant_id
        )

    def list_index_records(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> Sequence[IndexRecord]:
        rows = self._session.execute(
            select(RagIndexRecordRow)
            .join(
                DocumentVersionRow,
                RagIndexRecordRow.document_version_id == DocumentVersionRow.id,
            )
            .join(
                KnowledgeDocumentRow,
                DocumentVersionRow.document_id == KnowledgeDocumentRow.id,
            )
            .where(
                RagIndexRecordRow.document_version_id == str(document_version_id),
                KnowledgeDocumentRow.tenant_id == str(tenant_id),
            )
        ).scalars().all()
        return tuple(_index_from_row(row) for row in rows)

    def get_trusted_chunks(
        self, chunk_ids: Sequence[UUID], *, scope: AccessScope
    ) -> Sequence[TrustedChunkMetadata]:
        if not chunk_ids:
            return ()
        rows = self._session.execute(
            select(KnowledgeChunkRow, KnowledgeDocumentRow)
            .join(
                DocumentVersionRow,
                KnowledgeChunkRow.document_version_id == DocumentVersionRow.id,
            )
            .join(
                KnowledgeDocumentRow,
                DocumentVersionRow.document_id == KnowledgeDocumentRow.id,
            )
            .join(
                KnowledgeBaseRow,
                KnowledgeDocumentRow.knowledge_base_id == KnowledgeBaseRow.id,
            )
            .where(
                KnowledgeChunkRow.id.in_([str(value) for value in chunk_ids]),
                KnowledgeDocumentRow.tenant_id == str(scope.tenant_id),
                KnowledgeDocumentRow.status == DocumentStatus.PUBLISHED.value,
                KnowledgeDocumentRow.current_version_id == DocumentVersionRow.id,
                KnowledgeBaseRow.status == KnowledgeBaseStatus.PUBLISHED.value,
            )
        ).all()
        source_rows = self._session.execute(
            select(ChunkSourceRow).where(
                ChunkSourceRow.chunk_id.in_([chunk_row.id for chunk_row, _ in rows])
            )
        ).scalars().all()
        sources_by_chunk: dict[str, list[ChunkSourceRow]] = {}
        for source in source_rows:
            sources_by_chunk.setdefault(source.chunk_id, []).append(source)
        result: list[TrustedChunkMetadata] = []
        for chunk_row, document in rows:
            chunk = _chunk_from_row(chunk_row, sources_by_chunk.get(chunk_row.id, ()))
            knowledge_base_id = UUID(document.knowledge_base_id)
            if scope.allows(
                UUID(document.tenant_id),
                knowledge_base_id,
                chunk.sensitivity,
                chunk.permission_tags,
            ):
                result.append(
                    TrustedChunkMetadata(
                        chunk=chunk,
                        tenant_id=UUID(document.tenant_id),
                        knowledge_base_id=knowledge_base_id,
                        published=True,
                    )
                )
        return tuple(result)

    def save_index_records(
        self, records: Sequence[IndexRecord], *, tenant_id: UUID
    ) -> None:
        self._repository.save_index_records(self._session, records, tenant_id=tenant_id)

    def delete_index_records(self, document_version_id: UUID, *, tenant_id: UUID) -> None:
        visible = self.resolve_indexing_context(document_version_id, tenant_id=tenant_id)
        if visible is None:
            raise InvalidDocumentLifecycle("version is not visible to this tenant")
        self._session.execute(
            delete(RagIndexRecordRow).where(
                RagIndexRecordRow.document_version_id == str(document_version_id)
            )
        )
        self._session.flush()

    def mark_processing(self, context: IndexingContext, *, index_version: str) -> None:
        self._set_version_status(context, IndexStatus.PROCESSING)

    def mark_succeeded(self, context: IndexingContext, *, index_version: str) -> None:
        records = self.list_index_records(
            context.document_version_id, tenant_id=context.tenant_id
        )
        if not records or any(
            record.index_version != index_version
            or record.status is not IndexStatus.SUCCEEDED
            or record.vector_id is None
            or record.bm25_key is None
            for record in records
        ):
            raise InvalidDocumentLifecycle("cannot complete an incomplete index")
        self._set_version_status(context, IndexStatus.SUCCEEDED)

    def mark_failed(
        self, context: IndexingContext, *, category: str, cleanup_pending: bool
    ) -> None:
        status = IndexStatus.DELETE_PENDING if cleanup_pending else IndexStatus.FAILED
        self._set_version_status(context, status)
        if cleanup_pending:
            self._session.execute(
                update(RagIndexRecordRow)
                .where(RagIndexRecordRow.document_version_id == str(context.document_version_id))
                .values(
                    status=IndexStatus.DELETE_PENDING.value,
                    error_category=category,
                    updated_at=_utc(self._clock()),
                )
            )
            self._session.flush()

    def mark_delete_pending(self, context: IndexingContext) -> None:
        self._set_version_status(context, IndexStatus.DELETE_PENDING)

    def mark_deleted(self, context: IndexingContext) -> None:
        self._set_version_status(context, IndexStatus.DELETED)

    def _set_version_status(self, context: IndexingContext, status: IndexStatus) -> None:
        result = self._session.execute(
            update(DocumentVersionRow)
            .where(
                DocumentVersionRow.id == str(context.document_version_id),
                DocumentVersionRow.document_id == str(context.document_id),
            )
            .values(index_status=status.value)
        )
        if result.rowcount != 1:
            raise InvalidDocumentLifecycle("indexing context is stale")
        self._session.flush()
