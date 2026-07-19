from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID, uuid4

import pytest

from shieldchain.rag.domain import AccessScope, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.ports import (
    Bm25IndexError,
    Bm25Match,
    EmbeddingResponseError,
    VectorIndexUnavailableError,
    VectorMatch,
)
from shieldchain.rag.retrieval import (
    HybridRetrievalError,
    HybridRetrievalService,
    TrustedChunkMetadata,
)
from shieldchain.rag.rewrite import RewriteResult


def chunk(*, chunk_id: UUID | None = None, tags: tuple[str, ...] = ("soc",)) -> KnowledgeChunk:
    text = "critical vulnerability remediation"
    return KnowledgeChunk(
        id=chunk_id or uuid4(),
        document_version_id=uuid4(),
        ordinal=0,
        heading_path=("Runbook",),
        page_number=1,
        structural_location=None,
        text=text,
        token_count=3,
        content_sha256=sha256(text.encode()).hexdigest(),
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags=tags,
        chunking_mode="rule",
        is_degraded=False,
    )


@dataclass
class FakeBm25:
    results: dict[str, tuple[Bm25Match, ...]]
    error: Exception | None = None

    def search(self, query: str, *, scope: AccessScope, limit: int):
        if self.error:
            raise self.error
        return self.results.get(query, ())[:limit]


@dataclass
class FakeEmbedding:
    error: Exception | None = None
    malformed: bool = False

    def embed(self, texts, *, model: str):
        if self.error:
            raise self.error
        if self.malformed:
            return [[1.0]]
        return [[float(index), 1.0] for index, _ in enumerate(texts)]


@dataclass
class FakeVector:
    results: tuple[tuple[VectorMatch, ...], ...]
    error: Exception | None = None

    def __post_init__(self) -> None:
        self.calls = 0

    def search(self, vector, *, scope: AccessScope, limit: int):
        if self.error:
            raise self.error
        result = self.results[self.calls] if self.calls < len(self.results) else ()
        self.calls += 1
        return result[:limit]


@dataclass
class FakeMetadata:
    rows: tuple[TrustedChunkMetadata, ...]
    error: Exception | None = None

    def get_trusted_chunks(self, chunk_ids, *, scope: AccessScope):
        if self.error:
            raise self.error
        wanted = set(chunk_ids)
        return tuple(row for row in self.rows if row.chunk.id in wanted)


@pytest.fixture
def ids():
    return uuid4(), uuid4(), uuid4(), uuid4()


def access(tenant: UUID, base: UUID, *, tags: tuple[str, ...] = ("soc",)) -> AccessScope:
    return AccessScope(
        tenant_id=tenant,
        principal_id=uuid4(),
        roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=tags,
        knowledge_base_ids=(base,),
    )


def service(bm25, embedding, vector, metadata, **changes):
    return HybridRetrievalService(
        bm25=bm25,
        embedding=embedding,
        vector_index=vector,
        metadata_repository=metadata,
        **changes,
    )


def test_multi_query_rrf_is_stable_deduplicated_and_preserves_original(ids) -> None:
    tenant, base, first_id, second_id = ids
    first, second = chunk(chunk_id=first_id), chunk(chunk_id=second_id)
    bm25 = FakeBm25(
        {
            "原始问题": (Bm25Match(first.id, 8.0), Bm25Match(second.id, 4.0)),
            "rewritten": (Bm25Match(second.id, 9.0), Bm25Match(first.id, 3.0)),
        }
    )
    vector = FakeVector(
        (
            (VectorMatch(second.id, 0.9), VectorMatch(first.id, 0.8)),
            (VectorMatch(second.id, 0.95),),
        )
    )
    metadata = FakeMetadata(
        tuple(TrustedChunkMetadata(item, tenant, base, True) for item in (first, second))
    )

    result = service(bm25, FakeEmbedding(), vector, metadata).retrieve(
        "原始问题", ("rewritten", "rewritten"), scope=access(tenant, base)
    )

    assert result.original_query == "原始问题"
    assert result.executed_queries == ("原始问题", "rewritten")
    assert [item.chunk.id for item in result.matches] == [second.id, first.id]
    assert result.matches[0].fusion_score == pytest.approx(3 / 61 + 1 / 62)
    assert result.matches[0].bm25_ranks == (2, 1)
    assert result.matches[0].vector_ranks == (1, 1)
    assert result.degradations == ()


def test_result_assembly_rechecks_trusted_acl_and_publication(ids) -> None:
    tenant, base, allowed_id, denied_id = ids
    allowed = chunk(chunk_id=allowed_id)
    denied = chunk(chunk_id=denied_id, tags=("admin",))
    bm25 = FakeBm25(
        {"q": (Bm25Match(denied.id, 10), Bm25Match(allowed.id, 9))}
    )
    metadata = FakeMetadata(
        (
            TrustedChunkMetadata(denied, tenant, base, True),
            TrustedChunkMetadata(allowed, tenant, base, True),
        )
    )

    result = service(bm25, FakeEmbedding(), FakeVector(((),)), metadata).retrieve(
        "q", (), scope=access(tenant, base)
    )

    assert [item.chunk.id for item in result.matches] == [allowed.id]


@pytest.mark.parametrize("published", [False])
def test_missing_or_unpublished_trusted_metadata_fails_closed(ids, published) -> None:
    tenant, base, first_id, second_id = ids
    first, second = chunk(chunk_id=first_id), chunk(chunk_id=second_id)
    result = service(
        FakeBm25({"q": (Bm25Match(first.id, 2), Bm25Match(second.id, 1))}),
        FakeEmbedding(),
        FakeVector(((),)),
        FakeMetadata((TrustedChunkMetadata(first, tenant, base, published),)),
    ).retrieve("q", (), scope=access(tenant, base))
    assert result.matches == ()


@pytest.mark.parametrize(
    ("embedding_error", "vector_error", "category"),
    [
        (EmbeddingResponseError("bad"), None, "embedding_response"),
        (None, VectorIndexUnavailableError("down"), "vector_unavailable"),
    ],
)
def test_vector_failure_returns_real_bm25_only_without_fake_score(
    ids, embedding_error, vector_error, category
) -> None:
    tenant, base, first_id, _ = ids
    first = chunk(chunk_id=first_id)
    result = service(
        FakeBm25({"q": (Bm25Match(first.id, 3.5),)}),
        FakeEmbedding(error=embedding_error),
        FakeVector(((),), error=vector_error),
        FakeMetadata((TrustedChunkMetadata(first, tenant, base, True),)),
    ).retrieve("q", (), scope=access(tenant, base))

    assert result.matches[0].bm25_score == 3.5
    assert result.matches[0].vector_score is None
    assert result.degradations[0].kind.value == "vector_degraded"
    assert result.degradations[0].error_category == category


def test_malformed_embedding_count_degrades_before_vector_call(ids) -> None:
    tenant, base, first_id, _ = ids
    first = chunk(chunk_id=first_id)
    vector = FakeVector(((),))
    result = service(
        FakeBm25({"q": (Bm25Match(first.id, 1),), "q2": ()}),
        FakeEmbedding(malformed=True),
        vector,
        FakeMetadata((TrustedChunkMetadata(first, tenant, base, True),)),
    ).retrieve("q", ("q2",), scope=access(tenant, base))
    assert vector.calls == 0
    assert result.degradations[0].error_category == "embedding_response"


def test_bm25_failure_is_safely_classified_and_does_not_run_vector(ids) -> None:
    tenant, base, *_ = ids
    vector = FakeVector(((),))
    with pytest.raises(HybridRetrievalError, match="BM25 retrieval") as captured:
        service(
            FakeBm25({}, error=Bm25IndexError("secret provider detail")),
            FakeEmbedding(),
            vector,
            FakeMetadata(()),
        ).retrieve("q", (), scope=access(tenant, base))
    assert captured.value.category == "bm25_unavailable"
    assert "secret" not in str(captured.value)
    assert vector.calls == 0


def test_bm25_adapter_query_rejection_is_safely_classified(ids) -> None:
    tenant, base, *_ = ids

    class RejectingBm25(FakeBm25):
        def search(self, query, *, scope, limit):
            raise ValueError("tokenizer details")

    with pytest.raises(HybridRetrievalError) as captured:
        service(
            RejectingBm25({}), FakeEmbedding(), FakeVector(()), FakeMetadata(())
        ).retrieve("q", (), scope=access(tenant, base))
    assert captured.value.category == "bm25_query_rejected"
    assert "tokenizer" not in str(captured.value)


def test_malformed_or_oversized_adapter_responses_are_bounded(ids) -> None:
    tenant, base, first_id, _ = ids
    first = chunk(chunk_id=first_id)

    class BadBm25(FakeBm25):
        def search(self, query, *, scope, limit):
            return (Bm25Match(first.id, 1),) * (limit + 1)

    with pytest.raises(HybridRetrievalError) as captured:
        service(
            BadBm25({}), FakeEmbedding(), FakeVector(()), FakeMetadata(())
        ).retrieve("q", (), scope=access(tenant, base))
    assert captured.value.category == "bm25_response"

    class BadVector(FakeVector):
        def search(self, vector, *, scope, limit):
            return (VectorMatch(first.id, 0.5),) * (limit + 1)

    result = service(
        FakeBm25({"q": (Bm25Match(first.id, 1),)}),
        FakeEmbedding(),
        BadVector(()),
        FakeMetadata((TrustedChunkMetadata(first, tenant, base, True),)),
    ).retrieve("q", (), scope=access(tenant, base))
    assert result.matches[0].vector_score is None
    assert result.degradations[0].error_category == "vector_response"


@pytest.mark.parametrize(
    ("original", "rewrites", "message"),
    [
        ("", (), "original_query"),
        ("q", ("",), "non-empty"),
        ("q", ("a", "b"), "queries must not exceed"),
        ("12345", (), "max_query_characters"),
    ],
)
def test_query_count_and_length_are_bounded(original, rewrites, message) -> None:
    retriever = service(
        FakeBm25({}),
        FakeEmbedding(),
        FakeVector(()),
        FakeMetadata(()),
        max_queries=2,
        max_query_characters=4,
    )
    with pytest.raises(ValueError, match=message):
        retriever.retrieve(original, rewrites, scope=access(uuid4(), uuid4()))


def test_candidate_and_result_limits_are_deterministic(ids) -> None:
    tenant, base, *_ = ids
    chunks = tuple(chunk() for _ in range(4))
    bm25 = FakeBm25({"q": tuple(Bm25Match(item.id, 10 - rank) for rank, item in enumerate(chunks))})
    metadata = FakeMetadata(
        tuple(TrustedChunkMetadata(item, tenant, base, True) for item in chunks)
    )
    result = service(
        bm25,
        FakeEmbedding(),
        FakeVector(((),)),
        metadata,
        per_source_limit=3,
        max_candidates=2,
        max_results=2,
    ).retrieve("q", (), scope=access(tenant, base), limit=1)
    assert [item.chunk.id for item in result.matches] == [chunks[0].id]


def test_invalid_or_unrequested_metadata_is_rejected(ids) -> None:
    tenant, base, first_id, second_id = ids
    first, second = chunk(chunk_id=first_id), chunk(chunk_id=second_id)

    class BadMetadata(FakeMetadata):
        def get_trusted_chunks(self, chunk_ids, *, scope):
            return (TrustedChunkMetadata(second, tenant, base, True),)

    with pytest.raises(HybridRetrievalError) as captured:
        service(
            FakeBm25({"q": (Bm25Match(first.id, 1),)}),
            FakeEmbedding(),
            FakeVector(((),)),
            BadMetadata(()),
        ).retrieve("q", (), scope=access(tenant, base))
    assert captured.value.category == "metadata_response"


def test_rewrite_degradation_is_preserved_through_hybrid_retrieval(ids) -> None:
    tenant, base, first_id, _ = ids
    first = chunk(chunk_id=first_id)
    rewrite = RewriteResult(
        original_query="q",
        normalized_query="q",
        resolved_query="q",
        security_entities=(),
        queries=("q",),
        rewrite_degraded=True,
        failure_category="timeout",
        requested_model="deepseek-test",
        response_model=None,
        prompt_version="rewrite-v1",
        prompt_tokens=None,
        completion_tokens=None,
    )
    result = service(
        FakeBm25({"q": (Bm25Match(first.id, 1),)}),
        FakeEmbedding(error=EmbeddingResponseError("down")),
        FakeVector(()),
        FakeMetadata((TrustedChunkMetadata(first, tenant, base, True),)),
    ).retrieve_rewrite(rewrite, scope=access(tenant, base))

    assert result.executed_queries == ("q",)
    assert [item.kind.value for item in result.degradations] == [
        "rewrite_degraded",
        "vector_degraded",
    ]
    assert result.degradations[0].error_category == "timeout"


def test_maximum_valid_rewrite_query_count_is_accepted_by_default(ids) -> None:
    tenant, base, *_ = ids
    rewrite = RewriteResult(
        original_query="q",
        normalized_query="q1",
        resolved_query="q2",
        security_entities=(),
        queries=("q", "q1", "q2", "q3", "q4", "q5"),
        rewrite_degraded=False,
        failure_category=None,
        requested_model="deepseek-test",
        response_model="deepseek-test",
        prompt_version="rewrite-v1",
        prompt_tokens=1,
        completion_tokens=1,
    )
    result = service(
        FakeBm25({}), FakeEmbedding(), FakeVector(()), FakeMetadata(())
    ).retrieve_rewrite(rewrite, scope=access(tenant, base))

    assert result.executed_queries == rewrite.queries
