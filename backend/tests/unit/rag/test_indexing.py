from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.rag.bm25 import Bm25ScopeMetadata, DeterministicBm25Index
from shieldchain.rag.domain import IndexRecord, IndexStatus, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.indexing import (
    IndexingContext,
    IndexingOperationError,
    IndexingOutcome,
    IndexingService,
)
from shieldchain.rag.milvus import ManagedMilvusIndex
from shieldchain.rag.tokenization import DeterministicSecurityTokenizer

NOW = datetime(2026, 7, 19, tzinfo=UTC)


def chunk(version_id: UUID, ordinal: int = 0) -> KnowledgeChunk:
    return KnowledgeChunk(
        id=uuid4(),
        document_version_id=version_id,
        ordinal=ordinal,
        heading_path=("root",),
        page_number=None,
        structural_location=f"paragraph:{ordinal}",
        text=f"安全事件 {ordinal}",
        token_count=3,
        content_sha256=f"{ordinal + 1:064x}",
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags=("soc",),
        chunking_mode="rule",
        is_degraded=False,
    )


def record(value: KnowledgeChunk, *, kind: str, index_version: str = "v1") -> IndexRecord:
    return IndexRecord(
        id=uuid4(),
        document_version_id=value.document_version_id,
        chunk_id=value.id,
        bm25_key=str(value.id) if kind == "bm25" else None,
        embedding_model="BAAI/bge-m3" if kind == "vector" else None,
        vector_id=str(value.id) if kind == "vector" else None,
        reranker_model=None,
        index_version=index_version,
        status=IndexStatus.SUCCEEDED,
        error_category=None,
        updated_at=NOW,
    )


class FakeRepository:
    def __init__(self, context: IndexingContext, chunks: tuple[KnowledgeChunk, ...]) -> None:
        self.context = context
        self.chunks = chunks
        self.records: tuple[IndexRecord, ...] = ()
        self.events: list[str] = []
        self.save_calls = 0

    def resolve_indexing_context(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> IndexingContext | None:
        self.events.append("resolve")
        return self.context

    def list_chunks(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> tuple[KnowledgeChunk, ...]:
        return self.chunks

    def list_index_records(
        self, document_version_id: UUID, *, tenant_id: UUID
    ) -> tuple[IndexRecord, ...]:
        return self.records

    def save_index_records(
        self, records: tuple[IndexRecord, ...], *, tenant_id: UUID
    ) -> None:
        self.events.append("save_records")
        self.save_calls += 1
        self.records = tuple(records)

    def delete_index_records(self, document_version_id: UUID, *, tenant_id: UUID) -> None:
        self.events.append("delete_records")
        self.records = ()


class FakeLifecycle:
    def __init__(self, events: list[str], *, fail_succeeded: bool = False) -> None:
        self.events = events
        self.failures: list[tuple[str, bool]] = []
        self.fail_succeeded = fail_succeeded

    def mark_processing(self, context: IndexingContext, *, index_version: str) -> None:
        self.events.append("processing")

    def mark_succeeded(self, context: IndexingContext, *, index_version: str) -> None:
        self.events.append("succeeded")
        if self.fail_succeeded:
            raise RuntimeError("database commit failed")

    def mark_failed(
        self, context: IndexingContext, *, category: str, cleanup_pending: bool
    ) -> None:
        self.events.append("failed")
        self.failures.append((category, cleanup_pending))

    def mark_delete_pending(self, context: IndexingContext) -> None:
        self.events.append("delete_pending")

    def mark_deleted(self, context: IndexingContext) -> None:
        self.events.append("deleted")


class FakeEmbedding:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def embed(self, texts: list[str], *, model: str) -> tuple[tuple[float, ...], ...]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("secret provider failure")
        return tuple((float(position), 0.5) for position, _ in enumerate(texts))


class FakeIndex:
    def __init__(
        self,
        kind: str,
        events: list[str],
        *,
        fail_upsert: bool = False,
        fail_delete: bool = False,
    ) -> None:
        self.kind = kind
        self.events = events
        self.fail_upsert = fail_upsert
        self.fail_delete = fail_delete
        self.upsert_calls = 0
        self.contexts: list[IndexingContext] = []

    def upsert(self, chunks, vectors=None, *, context):
        self.events.append(f"{self.kind}_upsert")
        self.upsert_calls += 1
        self.contexts.append(context)
        if self.fail_upsert:
            raise RuntimeError("partial provider write")
        return tuple(record(value, kind=self.kind) for value in chunks)

    def delete_document_version(self, *, context: IndexingContext) -> None:
        self.events.append(f"{self.kind}_delete")
        self.contexts.append(context)
        if self.fail_delete:
            raise RuntimeError("provider delete failed")


class FakeMilvusClient:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def upsert(self, *, collection, data) -> None:
        self.rows.extend(data)

    def search(self, **kwargs):
        return []

    def delete(self, **kwargs) -> None:
        self.rows.clear()


@pytest.fixture
def setup():
    tenant_id, version_id = uuid4(), uuid4()
    context = IndexingContext(
        tenant_id=tenant_id,
        knowledge_base_id=uuid4(),
        document_id=uuid4(),
        document_version_id=version_id,
        published=False,
    )
    chunks = (chunk(version_id, 0), chunk(version_id, 1))
    repository = FakeRepository(context, chunks)
    lifecycle = FakeLifecycle(repository.events)
    embedding = FakeEmbedding()
    vector = FakeIndex("vector", repository.events)
    bm25 = FakeIndex("bm25", repository.events)
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )
    return context, repository, lifecycle, embedding, vector, bm25, service


def test_indexes_both_backends_and_persists_only_valid_complete_records(setup) -> None:
    context, repository, _, _, vector, bm25, service = setup

    result = service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert result.outcome is IndexingOutcome.SUCCEEDED
    assert result.record_count == 2
    assert repository.events == [
        "resolve",
        "processing",
        "vector_upsert",
        "bm25_upsert",
        "save_records",
        "succeeded",
    ]
    assert vector.contexts == [context]
    assert bm25.contexts == [context]


def test_real_bm25_and_milvus_adapters_share_the_indexing_contract(setup) -> None:
    context, repository, lifecycle, embedding, _, _, _ = setup
    milvus_client = FakeMilvusClient()
    vector = ManagedMilvusIndex(
        client=milvus_client,
        collection="knowledge",
        expected_dimension=2,
        index_version="v1",
    )
    bm25 = DeterministicBm25Index(
        DeterministicSecurityTokenizer(),
        scope_resolver=lambda _: Bm25ScopeMetadata(
            context.tenant_id, context.knowledge_base_id, context.published
        ),
        index_version="v1",
    )
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    result = service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert result.outcome is IndexingOutcome.SUCCEEDED
    assert len(repository.records) == len(repository.chunks)
    assert all(record.vector_id and record.bm25_key for record in repository.records)
    assert all(row["published"] is False for row in milvus_client.rows)


def test_embedding_failure_never_calls_indexes_or_fabricates_records(setup) -> None:
    context, repository, lifecycle, _, vector, bm25, _ = setup
    embedding = FakeEmbedding(fail=True)
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    with pytest.raises(IndexingOperationError) as caught:
        service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert caught.value.category == "embedding_failed"
    assert caught.value.cleanup_pending is False
    assert vector.upsert_calls == bm25.upsert_calls == repository.save_calls == 0
    assert repository.records == ()


@pytest.mark.parametrize("failing_kind", ["vector", "bm25"])
def test_partial_index_failure_compensates_both_backends(setup, failing_kind: str) -> None:
    context, repository, lifecycle, embedding, _, _, _ = setup
    vector = FakeIndex(
        "vector", repository.events, fail_upsert=failing_kind == "vector"
    )
    bm25 = FakeIndex("bm25", repository.events, fail_upsert=failing_kind == "bm25")
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    with pytest.raises(IndexingOperationError) as caught:
        service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert caught.value.cleanup_pending is False
    assert repository.events[-4:] == [
        "vector_delete",
        "bm25_delete",
        "delete_records",
        "failed",
    ]
    assert repository.records == ()


def test_failed_compensation_is_explicitly_cleanup_pending(setup) -> None:
    context, repository, lifecycle, embedding, _, _, _ = setup
    vector = FakeIndex("vector", repository.events, fail_delete=True)
    bm25 = FakeIndex("bm25", repository.events, fail_upsert=True)
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    with pytest.raises(IndexingOperationError) as caught:
        service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert caught.value.cleanup_pending is True
    assert lifecycle.failures == [("index_write_failed", True)]


def test_complete_retry_is_idempotent_and_does_not_touch_providers(setup) -> None:
    context, repository, _, embedding, vector, bm25, service = setup
    repository.records = tuple(
        IndexRecord(
            id=uuid4(),
            document_version_id=value.document_version_id,
            chunk_id=value.id,
            bm25_key=str(value.id),
            embedding_model="BAAI/bge-m3",
            vector_id=str(value.id),
            reranker_model=None,
            index_version="v1",
            status=IndexStatus.SUCCEEDED,
            error_category=None,
            updated_at=NOW,
        )
        for value in repository.chunks
    )

    result = service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert result.outcome is IndexingOutcome.ALREADY_SUCCEEDED
    assert embedding.calls == vector.upsert_calls == bm25.upsert_calls == 0
    assert repository.save_calls == 0


def test_cleanup_pending_retry_cleans_both_backends_before_reindexing(setup) -> None:
    context, repository, lifecycle, embedding, vector, bm25, _ = setup
    repository.context = IndexingContext(
        tenant_id=context.tenant_id,
        knowledge_base_id=context.knowledge_base_id,
        document_id=context.document_id,
        document_version_id=context.document_version_id,
        published=context.published,
        cleanup_pending=True,
    )
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    result = service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert result.outcome is IndexingOutcome.SUCCEEDED
    assert repository.events[1:5] == [
        "vector_delete",
        "bm25_delete",
        "delete_records",
        "processing",
    ]


def test_lifecycle_commit_failure_compensates_external_and_control_plane_records(setup) -> None:
    context, repository, _, embedding, vector, bm25, _ = setup
    lifecycle = FakeLifecycle(repository.events, fail_succeeded=True)
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    with pytest.raises(IndexingOperationError) as caught:
        service.index(context.document_version_id, tenant_id=context.tenant_id)

    assert caught.value.category == "commit_failed"
    assert caught.value.cleanup_pending is False
    assert repository.records == ()
    assert repository.events[-4:] == [
        "vector_delete",
        "bm25_delete",
        "delete_records",
        "failed",
    ]


def test_rebuild_deletes_external_then_records_before_new_write(setup) -> None:
    context, repository, _, _, _, _, service = setup

    result = service.rebuild(context.document_version_id, tenant_id=context.tenant_id)

    assert result.outcome is IndexingOutcome.SUCCEEDED
    assert repository.events[:4] == [
        "resolve",
        "vector_delete",
        "bm25_delete",
        "delete_records",
    ]


def test_delete_orders_external_cleanup_before_control_plane_deletion(setup) -> None:
    context, repository, _, _, _, _, service = setup

    result = service.delete(context.document_version_id, tenant_id=context.tenant_id)

    assert result.outcome is IndexingOutcome.DELETED
    assert repository.events == [
        "resolve",
        "delete_pending",
        "vector_delete",
        "bm25_delete",
        "delete_records",
        "deleted",
    ]


def test_partial_delete_keeps_records_and_marks_cleanup_pending(setup) -> None:
    context, repository, lifecycle, embedding, _, bm25, _ = setup
    vector = FakeIndex("vector", repository.events, fail_delete=True)
    service = IndexingService(
        repository=repository,
        lifecycle=lifecycle,
        embedding=embedding,
        vector_index=vector,
        bm25_index=bm25,
        embedding_model="BAAI/bge-m3",
        index_version="v1",
    )

    with pytest.raises(IndexingOperationError) as caught:
        service.delete(context.document_version_id, tenant_id=context.tenant_id)

    assert caught.value.cleanup_pending is True
    assert "delete_records" not in repository.events
    assert repository.events[-3:] == ["vector_delete", "bm25_delete", "failed"]


def test_tenant_and_version_context_cannot_be_expanded_by_caller(setup) -> None:
    context, repository, _, embedding, vector, bm25, service = setup
    attacker_tenant = uuid4()

    with pytest.raises(PermissionError):
        service.index(context.document_version_id, tenant_id=attacker_tenant)
    assert embedding.calls == vector.upsert_calls == bm25.upsert_calls == 0

    repository.context = IndexingContext(
        tenant_id=context.tenant_id,
        knowledge_base_id=uuid4(),
        document_id=uuid4(),
        document_version_id=uuid4(),
        published=True,
    )
    with pytest.raises(PermissionError):
        service.index(context.document_version_id, tenant_id=context.tenant_id)
    assert embedding.calls == vector.upsert_calls == bm25.upsert_calls == 0
