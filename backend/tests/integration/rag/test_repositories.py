from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from shieldchain.db.base import Base
from shieldchain.rag.domain import (
    AccessScope,
    ChunkingStatus,
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
from shieldchain.rag.repositories import InvalidDocumentLifecycle, SqlAlchemyKnowledgeRepository

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db_session:
        yield db_session
        db_session.rollback()


def make_base(*, tenant_id=None) -> KnowledgeBase:
    return KnowledgeBase(
        id=uuid4(),
        tenant_id=tenant_id or uuid4(),
        name="Runbooks",
        status=KnowledgeBaseStatus.PUBLISHED,
        default_sensitivity=SensitivityLevel.INTERNAL,
        version_policy="manual",
        created_at=NOW,
        updated_at=NOW,
    )


def make_document(base: KnowledgeBase) -> KnowledgeDocument:
    return KnowledgeDocument(
        id=uuid4(),
        knowledge_base_id=base.id,
        tenant_id=base.tenant_id,
        original_filename="runbook.md",
        storage_key="knowledge/server-generated",
        media_type="text/markdown",
        content_sha256="a" * 64,
        status=DocumentStatus.DRAFT,
        current_version_id=None,
        created_at=NOW,
        updated_at=NOW,
    )


def make_version(
    document: KnowledgeDocument,
    *,
    number: int = 1,
    index_status: IndexStatus = IndexStatus.SUCCEEDED,
    published_at: datetime | None = None,
) -> DocumentVersion:
    return DocumentVersion(
        id=uuid4(),
        document_id=document.id,
        version_number=number,
        parsing_status=ParsingStatus.SUCCEEDED,
        chunking_status=ChunkingStatus.SUCCEEDED,
        index_status=index_status,
        parser_name="markdown",
        parser_version="1",
        chunking_strategy="rule-v1",
        chunking_prompt_version=None,
        chunking_model=None,
        created_at=NOW,
        published_at=published_at,
    )


def make_chunk(version: DocumentVersion, *, ordinal=0) -> KnowledgeChunk:
    return KnowledgeChunk(
        id=uuid4(),
        document_version_id=version.id,
        ordinal=ordinal,
        heading_path=("Containment",),
        page_number=None,
        structural_location="section:1",
        text="Contain the endpoint.",
        token_count=4,
        content_sha256="b" * 64,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"security"},
        chunking_mode="rule",
        is_degraded=False,
    )


def make_index_record(version: DocumentVersion, chunk: KnowledgeChunk) -> IndexRecord:
    return IndexRecord(
        id=uuid4(),
        document_version_id=version.id,
        chunk_id=chunk.id,
        bm25_key="bm25:containment",
        embedding_model="bge-m3",
        vector_id="vector:containment",
        reranker_model=None,
        index_version="1",
        status=IndexStatus.SUCCEEDED,
        error_category=None,
        updated_at=NOW,
    )


def setup_document(session: Session):
    repository = SqlAlchemyKnowledgeRepository()
    base = make_base()
    document = make_document(base)
    repository.create_knowledge_base(session, base)
    repository.create_document(session, document)
    session.commit()
    return repository, base, document


def test_tenant_scoped_reads_never_return_another_tenants_rows(session: Session) -> None:
    repository, base, document = setup_document(session)
    other_tenant = uuid4()

    assert repository.get_knowledge_base(session, base.id, tenant_id=other_tenant) is None
    assert repository.get_document(session, document.id, tenant_id=other_tenant) is None
    assert repository.get_document(session, document.id, tenant_id=base.tenant_id) == document


def test_version_and_chunk_writes_are_idempotent_by_request_and_content(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    chunk = make_chunk(version)

    stored = repository.create_version(
        session, version, [chunk], tenant_id=base.tenant_id, idempotency_key="upload-1"
    )
    repeated = repository.create_version(
        session, version, [chunk], tenant_id=base.tenant_id, idempotency_key="upload-1"
    )
    session.commit()

    assert repeated == stored
    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (chunk,)


def test_index_record_writes_are_bound_to_the_server_tenant(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    chunk = make_chunk(version)
    repository.create_version(
        session, version, [chunk], tenant_id=base.tenant_id, idempotency_key="index-v1"
    )
    record = make_index_record(version, chunk)

    with pytest.raises(InvalidDocumentLifecycle):
        repository.save_index_records(session, [record], tenant_id=uuid4())
    repository.save_index_records(session, [record], tenant_id=base.tenant_id)


def test_publish_rollback_and_delete_pending_are_atomic_tenant_bound_transitions(
    session: Session,
) -> None:
    repository, base, document = setup_document(session)
    first = make_version(document)
    second = make_version(document, number=2)
    repository.create_version(
        session, first, [make_chunk(first)], tenant_id=base.tenant_id, idempotency_key="v1"
    )
    repository.create_version(
        session, second, [make_chunk(second)], tenant_id=base.tenant_id, idempotency_key="v2"
    )

    published = repository.publish_version(
        session, document.id, first.id, tenant_id=base.tenant_id, now=NOW
    )
    rolled_back = repository.rollback_to_version(
        session, document.id, first.id, tenant_id=base.tenant_id, now=NOW
    )
    pending = repository.mark_delete_pending(
        session, document.id, tenant_id=base.tenant_id, now=NOW
    )

    assert published.current_version_id == first.id
    assert rolled_back.current_version_id == first.id
    assert pending.status is DocumentStatus.DELETE_PENDING
    assert (
        repository.get_version(session, first.id, tenant_id=base.tenant_id).index_status
        is IndexStatus.DELETE_PENDING
    )
    assert (
        repository.get_version(session, second.id, tenant_id=base.tenant_id).index_status
        is IndexStatus.DELETE_PENDING
    )
    with pytest.raises(InvalidDocumentLifecycle):
        repository.publish_version(session, document.id, second.id, tenant_id=uuid4(), now=NOW)


def test_publish_requires_all_processing_and_index_states_to_succeed(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document, index_status=IndexStatus.PENDING)
    repository.create_version(
        session, version, [make_chunk(version)], tenant_id=base.tenant_id, idempotency_key="pending"
    )

    with pytest.raises(InvalidDocumentLifecycle):
        repository.publish_version(
            session, document.id, version.id, tenant_id=base.tenant_id, now=NOW
        )


def test_lifecycle_transitions_reject_naive_now_and_invalid_rollback_target(
    session: Session,
) -> None:
    repository, base, document = setup_document(session)
    published = make_version(document)
    never_published = make_version(document, number=2)
    repository.create_version(
        session,
        published,
        [make_chunk(published)],
        tenant_id=base.tenant_id,
        idempotency_key="published",
    )
    repository.create_version(
        session,
        never_published,
        [make_chunk(never_published)],
        tenant_id=base.tenant_id,
        idempotency_key="never-published",
    )

    with pytest.raises(ValueError):
        repository.publish_version(
            session,
            document.id,
            published.id,
            tenant_id=base.tenant_id,
            now=NOW.replace(tzinfo=None),
        )
    repository.publish_version(
        session, document.id, published.id, tenant_id=base.tenant_id, now=NOW
    )
    with pytest.raises(InvalidDocumentLifecycle):
        repository.rollback_to_version(
            session, document.id, never_published.id, tenant_id=base.tenant_id, now=NOW
        )

    other_repository, other_base, other_document = setup_document(session)
    other_version = make_version(other_document)
    other_repository.create_version(
        session,
        other_version,
        [make_chunk(other_version)],
        tenant_id=other_base.tenant_id,
        idempotency_key="draft-rollback",
    )
    with pytest.raises(InvalidDocumentLifecycle):
        other_repository.rollback_to_version(
            session,
            other_document.id,
            other_version.id,
            tenant_id=other_base.tenant_id,
            now=NOW,
        )


def test_citations_are_filtered_by_server_created_access_scope(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    chunk = make_chunk(version)
    repository.create_version(
        session, version, [chunk], tenant_id=base.tenant_id, idempotency_key="v1"
    )
    repository.publish_version(session, document.id, version.id, tenant_id=base.tenant_id, now=NOW)
    scope = AccessScope(
        base.tenant_id, uuid4(), {"reader"}, {SensitivityLevel.INTERNAL}, {"security"}, {base.id}
    )

    assert len(repository.list_citations(session, [chunk.id], scope=scope)) == 1
    denied = AccessScope(
        base.tenant_id, uuid4(), {"reader"}, {SensitivityLevel.INTERNAL}, {"other"}, {base.id}
    )
    assert repository.list_citations(session, [chunk.id], scope=denied) == ()
