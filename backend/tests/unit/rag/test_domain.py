from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

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
    RefusalReason,
    RetrievalDegradation,
    RetrievalDegradationKind,
    SensitivityLevel,
    StructuredRefusal,
)

NOW = datetime(2026, 7, 18, 8, 0, tzinfo=UTC)


def make_scope(**changes: object) -> AccessScope:
    values: dict[str, object] = {
        "tenant_id": uuid4(),
        "principal_id": uuid4(),
        "roles": {"knowledge_reader"},
        "allowed_sensitivities": {SensitivityLevel.INTERNAL},
        "permission_tags": {"security"},
        "knowledge_base_ids": {uuid4()},
    }
    values.update(changes)
    return AccessScope(**values)  # type: ignore[arg-type]


def make_knowledge_base(**changes: object) -> KnowledgeBase:
    values: dict[str, object] = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "name": "Security runbooks",
        "status": KnowledgeBaseStatus.PUBLISHED,
        "default_sensitivity": SensitivityLevel.INTERNAL,
        "version_policy": "manual",
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(changes)
    return KnowledgeBase(**values)  # type: ignore[arg-type]


def make_document(**changes: object) -> KnowledgeDocument:
    base = make_knowledge_base()
    values: dict[str, object] = {
        "id": uuid4(),
        "knowledge_base_id": base.id,
        "tenant_id": base.tenant_id,
        "original_filename": "runbook.md",
        "storage_key": "knowledge/5d2f4bce-9e56-49e4-b74d-cf9c063cb8a2",
        "media_type": "text/markdown",
        "content_sha256": "a" * 64,
        "status": DocumentStatus.PUBLISHED,
        "current_version_id": uuid4(),
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(changes)
    return KnowledgeDocument(**values)  # type: ignore[arg-type]


def make_version(**changes: object) -> DocumentVersion:
    document = make_document()
    values: dict[str, object] = {
        "id": uuid4(),
        "document_id": document.id,
        "version_number": 1,
        "parsing_status": ParsingStatus.SUCCEEDED,
        "chunking_status": ChunkingStatus.SUCCEEDED,
        "index_status": IndexStatus.SUCCEEDED,
        "parser_name": "markdown",
        "parser_version": "1",
        "chunking_strategy": "rule-v1",
        "chunking_prompt_version": None,
        "chunking_model": None,
        "created_at": NOW,
        "published_at": NOW,
    }
    values.update(changes)
    return DocumentVersion(**values)  # type: ignore[arg-type]


def test_document_version_rejects_unbounded_chunking_failure_text() -> None:
    with pytest.raises(ValueError, match="safe category"):
        make_version(chunking_failure_category="connection failed at secret.internal")


def make_chunk(**changes: object) -> KnowledgeChunk:
    version = make_version()
    values: dict[str, object] = {
        "id": uuid4(),
        "document_version_id": version.id,
        "ordinal": 0,
        "heading_path": ("Incident response",),
        "page_number": 1,
        "structural_location": "section:1",
        "text": "Contain the endpoint before collecting volatile evidence.",
        "token_count": 9,
        "content_sha256": "b" * 64,
        "sensitivity": SensitivityLevel.INTERNAL,
        "permission_tags": {"security"},
        "chunking_mode": "rule",
        "is_degraded": False,
    }
    values.update(changes)
    return KnowledgeChunk(**values)  # type: ignore[arg-type]


def test_domain_value_objects_are_frozen_and_copy_collections() -> None:
    scope = make_scope()
    chunk = make_chunk()

    with pytest.raises(FrozenInstanceError):
        scope.principal_id = uuid4()
    with pytest.raises(AttributeError):
        scope.roles.add("admin")
    with pytest.raises(AttributeError):
        chunk.permission_tags.add("production")


def test_chunk_sources_are_immutable_and_strictly_source_addressable() -> None:
    chunk = make_chunk()
    source = ChunkSource(
        chunk_id=chunk.id,
        occurrence_ordinal=0,
        parsed_element_ordinal=1,
        start_offset=2,
        end_offset=8,
        heading_path=("Incident response",),
        page_number=1,
        structural_location="line:2",
    )

    assert source.heading_path == ("Incident response",)
    with pytest.raises(FrozenInstanceError):
        source.end_offset = 9
    with pytest.raises(ValueError):
        ChunkSource(chunk.id, 0, 1, 4, 4, ("Heading",), None, "line:1")


def test_access_scope_is_default_deny_and_cannot_expand_from_a_result() -> None:
    scope = make_scope(knowledge_base_ids=set())
    assert not scope.allows(uuid4(), uuid4(), SensitivityLevel.PUBLIC, set())

    allowed_scope = make_scope()
    knowledge_base_id = next(iter(allowed_scope.knowledge_base_ids))
    assert allowed_scope.allows(
        allowed_scope.tenant_id, knowledge_base_id, SensitivityLevel.INTERNAL, {"security"}
    )
    assert not allowed_scope.allows(
        allowed_scope.tenant_id, knowledge_base_id, SensitivityLevel.INTERNAL, {"security", "admin"}
    )
    assert not allowed_scope.allows(
        uuid4(), knowledge_base_id, SensitivityLevel.INTERNAL, {"security"}
    )


@pytest.mark.parametrize("field", ["tenant_id", "principal_id"])
def test_access_scope_requires_uuid_identities(field: str) -> None:
    with pytest.raises(TypeError):
        make_scope(**{field: "not-a-uuid"})


@pytest.mark.parametrize("field", ["roles", "allowed_sensitivities", "permission_tags"])
def test_access_scope_rejects_empty_authorization_inputs(field: str) -> None:
    with pytest.raises(ValueError):
        make_scope(**{field: set()})


def test_knowledge_entities_preserve_lifecycle_and_index_metadata() -> None:
    base = make_knowledge_base()
    document = make_document(knowledge_base_id=base.id, tenant_id=base.tenant_id)
    version = make_version(document_id=document.id)
    chunk = make_chunk(document_version_id=version.id)
    index = IndexRecord(
        id=uuid4(),
        document_version_id=version.id,
        chunk_id=chunk.id,
        bm25_key="bm25:chunk",
        embedding_model="bge-m3",
        vector_id="milvus:chunk",
        reranker_model="bge-reranker-v2-m3",
        index_version="1",
        status=IndexStatus.SUCCEEDED,
        error_category=None,
        updated_at=NOW,
    )

    assert document.current_version_id is not None
    assert version.published_at == NOW
    assert index.vector_id == "milvus:chunk"


@pytest.mark.parametrize(
    "factory",
    [
        lambda: make_knowledge_base(name=" "),
        lambda: make_document(content_sha256="A" * 64),
        lambda: make_version(version_number=0),
        lambda: make_chunk(ordinal=-1),
        lambda: make_chunk(token_count=0),
        lambda: make_chunk(heading_path=()),
        lambda: make_chunk(permission_tags={" "}),
    ],
)
def test_domain_entities_reject_invalid_required_values(factory: Callable[[], object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        factory()


def test_datetimes_must_be_aware_utc() -> None:
    assert make_knowledge_base(created_at=NOW.replace(tzinfo=UTC)).created_at == NOW
    with pytest.raises(ValueError):
        make_knowledge_base(created_at=datetime(2026, 7, 18, 8, 0))


def test_citation_requires_complete_traceable_fields_and_valid_scores() -> None:
    base = make_knowledge_base()
    document = make_document(knowledge_base_id=base.id, tenant_id=base.tenant_id)
    version = make_version(document_id=document.id)
    chunk = make_chunk(document_version_id=version.id)
    citation = Citation(
        knowledge_base_id=base.id,
        document_id=document.id,
        document_version_id=version.id,
        chunk_id=chunk.id,
        heading_path=chunk.heading_path,
        page_number=chunk.page_number,
        structural_location=chunk.structural_location,
        excerpt=chunk.text,
        bm25_score=0.4,
        vector_score=0.6,
        fusion_score=0.7,
        reranker_score=0.8,
        updated_at=NOW,
        integrity_sha256=chunk.content_sha256,
    )
    assert citation.reranker_score == 0.8

    with pytest.raises(ValueError):
        replace(citation, fusion_score=1.1)


def test_degradation_and_structured_refusal_are_explicit_and_immutable() -> None:
    degraded = RetrievalDegradation(
        kind=RetrievalDegradationKind.VECTOR_DEGRADED,
        error_category="unavailable",
        message="Vector retrieval is unavailable; BM25 results only.",
    )
    refusal = StructuredRefusal(
        reason=RefusalReason.INSUFFICIENT_EVIDENCE,
        message="No authorized evidence supports an answer.",
        original_query="How do I contain this host?",
        citations=(),
        degradations=(degraded,),
    )

    assert refusal.reason is RefusalReason.INSUFFICIENT_EVIDENCE
    with pytest.raises(FrozenInstanceError):
        degraded.message = "changed"


def test_structural_locations_respect_the_persistence_contract() -> None:
    chunk = make_chunk()
    with pytest.raises(ValueError, match="512"):
        replace(chunk, structural_location="x" * 513)
    with pytest.raises(ValueError, match="512"):
        ChunkSource(chunk.id, 0, 0, 0, 1, ("Heading",), None, "x" * 513)
