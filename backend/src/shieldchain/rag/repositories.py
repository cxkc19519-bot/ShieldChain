"""Tenant-bound SQLAlchemy repository for the RAG control plane."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from sqlalchemy import select, update
from sqlalchemy.orm import Session

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
from shieldchain.rag.persistence import (
    ChunkSourceRow,
    DocumentVersionRow,
    KnowledgeBaseRow,
    KnowledgeChunkRow,
    KnowledgeDocumentRow,
    RagIndexRecordRow,
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
                    created_at=version.created_at,
                    published_at=version.published_at,
                )
            )
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
                            uuid5(
                                _SOURCE_NAMESPACE, f"{source.chunk_id}:{source.occurrence_ordinal}"
                            )
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
            session.flush()
        return version

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
