import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from shieldchain.db.base import Base
from shieldchain.rag.chunking import ChunkedItem, DeterministicChunker
from shieldchain.rag.domain import (
    AccessScope,
    ChunkingStatus,
    ChunkSource,
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
from shieldchain.rag.parsing import BoundedDocumentParser
from shieldchain.rag.persistence import DocumentVersionRow, RagIndexRecordRow
from shieldchain.rag.ports import ChunkBoundary, ParsedContent, ParsedElement
from shieldchain.rag.repositories import (
    InvalidDocumentLifecycle,
    SqlAlchemyIndexingUnitOfWork,
    SqlAlchemyKnowledgeRepository,
)
from shieldchain.rag.semantic_chunking import (
    SemanticChunkingAudit,
    SemanticChunkingResult,
    build_semantic_items,
    semantic_retry_key,
)

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
    chunk_id = uuid4()
    return KnowledgeChunk(
        id=chunk_id,
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
        sources=(ChunkSource(chunk_id, 0, ordinal, 0, 21, ("Containment",), None, "section:1"),),
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


def degraded_version(document: KnowledgeDocument) -> DocumentVersion:
    version = make_version(document, index_status=IndexStatus.PENDING)
    candidate = degraded_chunk(version)
    retry_key = semantic_retry_key(
        [candidate],
        version.id,
        strategy_version="hybrid-semantic-v1",
        prompt_version="semantic-boundaries-v1",
        requested_model="deepseek-test",
    )
    return replace(
        version,
        chunking_strategy="hybrid-semantic-v1",
        chunking_prompt_version="semantic-boundaries-v1",
        chunking_model="deepseek-test",
        chunking_failure_category="unavailable",
        chunking_retry_key=retry_key,
        chunking_requested_model="deepseek-test",
    )


def degraded_chunk(version: DocumentVersion) -> KnowledgeChunk:
    return replace(make_chunk(version), chunking_mode="rule_degraded", is_degraded=True)


def semantic_result(version: DocumentVersion, chunk: KnowledgeChunk) -> SemanticChunkingResult:
    boundaries = (ChunkBoundary(0, 1),)
    items = build_semantic_items(
        (ChunkedItem(chunk, chunk.sources),),
        boundaries,
        document_version_id=version.id,
    )
    return SemanticChunkingResult(
        items=items,
        boundaries=boundaries,
        audit=SemanticChunkingAudit(
            version.id,
            "hybrid-semantic-v1",
            "semantic-boundaries-v1",
            "deepseek-test",
            "deepseek-test",
            "semantic",
            None,
            None,
            10,
            2,
        ),
        retry_key=version.chunking_retry_key or "",
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


def test_degraded_chunks_upgrade_atomically_and_repeat_as_exact_noop(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="retry"
    )
    result = semantic_result(version, fallback)

    upgraded = repository.upgrade_semantic_chunking(session, result, tenant_id=base.tenant_id)
    repeated = repository.upgrade_semantic_chunking(session, result, tenant_id=base.tenant_id)
    session.commit()

    assert upgraded == repeated
    assert upgraded.chunking_failure_category is None
    assert upgraded.chunking_retry_key == version.chunking_retry_key
    assert upgraded.index_status is IndexStatus.PENDING
    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (
        result.items[0].chunk,
    )


def test_semantic_upgrade_is_tenant_scoped(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="scope"
    )

    with pytest.raises(InvalidDocumentLifecycle, match="not visible"):
        repository.upgrade_semantic_chunking(
            session, semantic_result(version, fallback), tenant_id=uuid4()
        )
    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (fallback,)


def test_semantic_upgrade_rolls_back_chunk_and_audit_replacement(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="rollback"
    )
    session.commit()
    original_add = repository._add_chunks

    def fail_after_insert(db_session: Session, chunks: tuple[KnowledgeChunk, ...]) -> None:
        original_add(db_session, chunks)
        db_session.flush()
        raise RuntimeError("injected failure")

    monkeypatch.setattr(repository, "_add_chunks", fail_after_insert)
    with pytest.raises(RuntimeError, match="injected"):
        repository.upgrade_semantic_chunking(
            session, semantic_result(version, fallback), tenant_id=base.tenant_id
        )

    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (fallback,)
    stored = repository.get_version(session, version.id, tenant_id=base.tenant_id)
    assert stored is not None
    assert stored.chunking_failure_category == "unavailable"
    assert stored.index_status is IndexStatus.PENDING


def test_semantic_upgrade_refuses_indexed_fallback_and_keeps_cleanup_reference(
    session: Session,
) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="indexed"
    )
    record = make_index_record(version, fallback)
    repository.save_index_records(session, [record], tenant_id=base.tenant_id)

    with pytest.raises(InvalidDocumentLifecycle, match="external indexes"):
        repository.upgrade_semantic_chunking(
            session, semantic_result(version, fallback), tenant_id=base.tenant_id
        )

    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (fallback,)
    assert session.get(RagIndexRecordRow, str(record.id)) is not None


def test_create_version_rejects_inconsistent_degraded_retry_audit(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    fallback = replace(make_chunk(version), chunking_mode="rule_degraded", is_degraded=True)
    with pytest.raises(InvalidDocumentLifecycle, match="complete retry audit"):
        repository.create_version(
            session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="missing-audit"
        )

    failed_clean = replace(version, chunking_failure_category="unavailable")
    with pytest.raises(InvalidDocumentLifecycle, match="requires degraded"):
        repository.create_version(
            session,
            failed_clean,
            [make_chunk(failed_clean)],
            tenant_id=base.tenant_id,
            idempotency_key="false-failure",
        )

    audited = degraded_version(document)
    audited_fallback = degraded_chunk(audited)
    with pytest.raises(InvalidDocumentLifecycle, match="retry key is invalid"):
        repository.create_version(
            session,
            replace(audited, chunking_retry_key="d" * 64),
            [audited_fallback],
            tenant_id=base.tenant_id,
            idempotency_key="forged-retry",
        )
    with pytest.raises(InvalidDocumentLifecycle, match="requested model consistently"):
        repository.create_version(
            session,
            replace(audited, chunking_model="different-model"),
            [audited_fallback],
            tenant_id=base.tenant_id,
            idempotency_key="conflicting-model",
        )


def test_rule_structural_split_is_not_misclassified_as_llm_fallback(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    structural = replace(
        make_chunk(version), chunking_mode="rule_structural_split", is_degraded=True
    )

    stored = repository.create_version(
        session,
        version,
        [structural],
        tenant_id=base.tenant_id,
        idempotency_key="structural",
    )

    assert stored.chunking_failure_category is None
    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (structural,)


def test_semantic_upgrade_cannot_change_acl_or_source_provenance(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="integrity"
    )
    result = semantic_result(version, fallback)
    expanded = replace(
        result.items[0].chunk,
        permission_tags=frozenset({"security", "admin"}),
    )
    with pytest.raises(InvalidDocumentLifecycle, match="ACL"):
        repository.upgrade_semantic_chunking(
            session,
            replace(result, items=(ChunkedItem(expanded, expanded.sources),)),
            tenant_id=base.tenant_id,
        )
    forged_sources = tuple(
        replace(source, structural_location="section:forged")
        for source in result.items[0].sources
    )
    forged = replace(result.items[0].chunk, sources=forged_sources)
    with pytest.raises(InvalidDocumentLifecycle, match="provenance"):
        repository.upgrade_semantic_chunking(
            session,
            replace(result, items=(ChunkedItem(forged, forged_sources),)),
            tenant_id=base.tenant_id,
        )


def test_semantic_upgrade_replays_boundaries_and_rejects_forged_output(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="replay"
    )
    result = semantic_result(version, fallback)
    forged_text = "FORGED"
    digest = hashlib.sha256(forged_text.encode()).hexdigest()
    forged_id = DeterministicChunker._id_for(version.id, digest)
    sources = tuple(replace(source, chunk_id=forged_id) for source in result.items[0].sources)
    forged_chunk = replace(
        result.items[0].chunk,
        id=forged_id,
        text=forged_text,
        token_count=1,
        content_sha256=digest,
        sources=sources,
    )
    forged = replace(result, items=(ChunkedItem(forged_chunk, sources),))
    with pytest.raises(InvalidDocumentLifecycle, match="does not match its boundaries"):
        repository.upgrade_semantic_chunking(session, forged, tenant_id=base.tenant_id)

    invalid_boundaries = replace(result, boundaries=())
    with pytest.raises(InvalidDocumentLifecycle, match="boundaries are invalid"):
        repository.upgrade_semantic_chunking(
            session, invalid_boundaries, tenant_id=base.tenant_id
        )


def test_semantic_upgrade_recomputes_retry_key_and_rejects_forged_audit(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="audit"
    )
    result = semantic_result(version, fallback)
    forged_audit = replace(result.audit, requested_model="forged-model")
    with pytest.raises(InvalidDocumentLifecycle, match="persisted intent"):
        repository.upgrade_semantic_chunking(
            session, replace(result, audit=forged_audit), tenant_id=base.tenant_id
        )
    with pytest.raises(InvalidDocumentLifecycle, match="retry key does not match"):
        repository.upgrade_semantic_chunking(
            session, replace(result, retry_key="d" * 64), tenant_id=base.tenant_id
        )

    other_repository, other_base, other_document = setup_document(session)
    bad_version = degraded_version(other_document)
    bad_fallback = degraded_chunk(bad_version)
    other_repository.create_version(
        session,
        bad_version,
        [bad_fallback],
        tenant_id=other_base.tenant_id,
        idempotency_key="bad-stored-key",
    )
    row = session.get(DocumentVersionRow, str(bad_version.id))
    assert row is not None
    row.chunking_retry_key = "c" * 64
    session.flush()
    bad_result = replace(semantic_result(bad_version, bad_fallback), retry_key="c" * 64)
    with pytest.raises(InvalidDocumentLifecycle, match="persisted semantic retry key"):
        other_repository.upgrade_semantic_chunking(
            session, bad_result, tenant_id=other_base.tenant_id
        )


def test_semantic_upgrade_never_revives_delete_pending_version(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = degraded_version(document)
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key="deleting"
    )
    repository.mark_delete_pending(session, document.id, tenant_id=base.tenant_id, now=NOW)

    with pytest.raises(InvalidDocumentLifecycle, match="deleting"):
        repository.upgrade_semantic_chunking(
            session, semantic_result(version, fallback), tenant_id=base.tenant_id
        )

    stored = repository.get_version(session, version.id, tenant_id=base.tenant_id)
    assert stored is not None and stored.index_status is IndexStatus.DELETE_PENDING
    assert repository.list_chunks(session, version.id, tenant_id=base.tenant_id) == (fallback,)


@pytest.mark.parametrize(
    ("parsing_status", "chunking_status", "index_status"),
    [
        (ParsingStatus.FAILED, ChunkingStatus.SUCCEEDED, IndexStatus.PENDING),
        (ParsingStatus.SUCCEEDED, ChunkingStatus.FAILED, IndexStatus.PENDING),
        (ParsingStatus.SUCCEEDED, ChunkingStatus.SUCCEEDED, IndexStatus.PROCESSING),
        (ParsingStatus.SUCCEEDED, ChunkingStatus.SUCCEEDED, IndexStatus.SUCCEEDED),
    ],
)
def test_semantic_upgrade_rejects_incomplete_or_active_processing_states(
    session: Session,
    parsing_status: ParsingStatus,
    chunking_status: ChunkingStatus,
    index_status: IndexStatus,
) -> None:
    repository, base, document = setup_document(session)
    version = replace(
        degraded_version(document),
        parsing_status=parsing_status,
        chunking_status=chunking_status,
        index_status=index_status,
    )
    fallback = degraded_chunk(version)
    repository.create_version(
        session, version, [fallback], tenant_id=base.tenant_id, idempotency_key=str(index_status)
    )

    with pytest.raises(InvalidDocumentLifecycle, match="inactive index"):
        repository.upgrade_semantic_chunking(
            session, semantic_result(version, fallback), tenant_id=base.tenant_id
        )


def test_semantic_upgrade_lock_contract_orders_document_before_version() -> None:
    statement = SqlAlchemyKnowledgeRepository._document_for_version_lock_statement(
        uuid4(), uuid4()
    )
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE OF knowledge_documents" in sql


def test_first_semantic_create_requires_complete_recomputable_audit(session: Session) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document, index_status=IndexStatus.PENDING)
    rule = DeterministicChunker().chunk(
        ParsedContent(
            text="contain endpoint. preserve evidence.",
            media_type="text/plain",
            metadata={"title": "Runbook"},
            elements=(
                ParsedElement("paragraph", "contain endpoint. ", "line:1"),
                ParsedElement("paragraph", "preserve evidence.", "line:2"),
            ),
        ),
        document_version_id=version.id,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"security"},
    )
    boundaries = (ChunkBoundary(0, 2),)
    items = build_semantic_items(rule.items, boundaries, document_version_id=version.id)
    audit = SemanticChunkingAudit(
        version.id,
        "hybrid-semantic-v1",
        "semantic-boundaries-v1",
        "deepseek-requested",
        "deepseek-actual",
        "semantic",
        None,
        None,
        10,
        2,
    )
    retry_key = semantic_retry_key(
        rule.items,
        version.id,
        strategy_version=audit.strategy_version,
        prompt_version=audit.prompt_version,
        requested_model=audit.requested_model,
    )
    result = SemanticChunkingResult(items, boundaries, audit, retry_key)
    audited = replace(
        version,
        chunking_strategy=audit.strategy_version,
        chunking_prompt_version=audit.prompt_version,
        chunking_model="deepseek-actual",
        chunking_requested_model="deepseek-requested",
        chunking_retry_key=retry_key,
    )

    with pytest.raises(InvalidDocumentLifecycle, match="create_version_from_semantic_result"):
        repository.create_version(
            session,
            audited,
            [item.chunk for item in items],
            tenant_id=base.tenant_id,
            idempotency_key="unsafe-semantic",
        )
    forged_item = replace(
        rule.items[0], chunk=replace(rule.items[0].chunk, text="FORGED")
    )
    forged_rule = replace(rule, items=(forged_item, *rule.items[1:]))
    with pytest.raises(InvalidDocumentLifecycle, match="rule input is invalid"):
        repository.create_version_from_semantic_result(
            session,
            audited,
            forged_rule,
            result,
            tenant_id=base.tenant_id,
            idempotency_key="forged-rule",
        )
    stored = repository.create_version_from_semantic_result(
        session,
        audited,
        rule,
        result,
        tenant_id=base.tenant_id,
        idempotency_key="semantic-first",
    )
    assert stored.chunking_requested_model == "deepseek-requested"

def test_chunk_source_occurrences_round_trip_without_cross_tenant_visibility(
    session: Session,
) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    chunk = make_chunk(version)
    duplicate = ChunkSource(chunk.id, 1, 9, 0, 21, ("Containment",), None, "section:10")
    chunk = replace(chunk, sources=chunk.sources + (duplicate,))
    repository.create_version(
        session, version, [chunk], tenant_id=base.tenant_id, idempotency_key="sources"
    )
    session.commit()

    stored = repository.list_chunks(session, version.id, tenant_id=base.tenant_id)
    assert stored == (chunk,)
    assert repository.list_chunks(session, version.id, tenant_id=uuid4()) == ()


def test_parsed_markdown_chunks_and_duplicate_sources_round_trip_tenant_scoped(
    session: Session,
) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document)
    parsed = BoundedDocumentParser().parse(
        b"# Guide\n```powershell\nGet-Process\nGet-Service\n```\n"
        b"2026-07-18 12:00:01 ERROR denied\n"
        b"2026-07-18 12:00:01 ERROR denied\n",
        filename="guide.md",
        media_type="text/markdown",
    )
    result = DeterministicChunker().chunk(
        parsed,
        document_version_id=version.id,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"security"},
    )
    repository.create_version(
        session,
        version,
        [item.chunk for item in result.items],
        tenant_id=base.tenant_id,
        idempotency_key="parsed-chunks",
    )
    session.commit()

    stored = repository.list_chunks(session, version.id, tenant_id=base.tenant_id)
    code = next(chunk for chunk in stored if "Get-Process" in chunk.text)
    log = next(chunk for chunk in stored if "ERROR denied" in chunk.text)
    assert code.chunking_mode == "rule"
    assert code.is_degraded is False
    assert code.sources[0].parsed_element_ordinal == 1
    assert code.sources[0].start_offset == 0
    assert code.sources[0].end_offset == len(code.text)
    assert code.sources[0].structural_location == "line:2-5;language:powershell"
    assert len(log.sources) == 2
    assert [source.parsed_element_ordinal for source in log.sources] == [2, 3]
    assert repository.list_chunks(session, version.id, tenant_id=uuid4()) == ()


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


def test_indexing_unit_of_work_resolves_authority_and_persists_lifecycle(
    session: Session,
) -> None:
    repository, base, document = setup_document(session)
    version = make_version(document, index_status=IndexStatus.PENDING)
    item = make_chunk(version)
    repository.create_version(
        session, version, [item], tenant_id=base.tenant_id, idempotency_key="index-uow"
    )
    unit = SqlAlchemyIndexingUnitOfWork(session, repository=repository, clock=lambda: NOW)

    context = unit.resolve_indexing_context(version.id, tenant_id=base.tenant_id)
    assert context is not None and context.published is False
    assert unit.resolve_indexing_context(version.id, tenant_id=uuid4()) is None
    unit.mark_processing(context, index_version="1")
    unit.save_index_records([make_index_record(version, item)], tenant_id=base.tenant_id)
    unit.mark_succeeded(context, index_version="1")

    assert unit.list_chunks(version.id, tenant_id=base.tenant_id) == (item,)
    assert len(unit.list_index_records(version.id, tenant_id=base.tenant_id)) == 1
    assert (
        repository.get_version(session, version.id, tenant_id=base.tenant_id).index_status
        is IndexStatus.SUCCEEDED
    )
    repository.publish_version(
        session, document.id, version.id, tenant_id=base.tenant_id, now=NOW
    )
    scope = AccessScope(
        tenant_id=base.tenant_id,
        principal_id=uuid4(),
        roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=("security",),
        knowledge_base_ids=(base.id,),
    )
    trusted = unit.get_trusted_chunks((item.id,), scope=scope)
    assert len(trusted) == 1 and trusted[0].chunk.id == item.id
    denied_scope = AccessScope(
        tenant_id=base.tenant_id,
        principal_id=uuid4(),
        roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=("other",),
        knowledge_base_ids=(base.id,),
    )
    assert unit.get_trusted_chunks((item.id,), scope=denied_scope) == ()

    unit.mark_failed(context, category="cleanup", cleanup_pending=True)
    retry = unit.resolve_indexing_context(version.id, tenant_id=base.tenant_id)
    assert retry is not None and retry.cleanup_pending is True
    unit.delete_index_records(version.id, tenant_id=base.tenant_id)
    assert unit.list_index_records(version.id, tenant_id=base.tenant_id) == ()


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
