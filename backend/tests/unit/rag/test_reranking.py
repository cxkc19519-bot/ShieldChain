from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID, uuid4

import httpx
import pytest

from shieldchain.rag.domain import (
    KnowledgeChunk,
    RetrievalDegradation,
    RetrievalDegradationKind,
    SensitivityLevel,
)
from shieldchain.rag.ports import (
    RerankedMatch,
    RerankerAuthenticationError,
    RerankerRateLimitError,
    RerankerResponseError,
    RerankerUnavailableError,
)
from shieldchain.rag.reranking import (
    BgeRerankerV2M3Http,
    RerankerMetrics,
    RerankingService,
)
from shieldchain.rag.retrieval import (
    FusedRetrievalMatch,
    HybridRetrievalResult,
)


def chunk(text: str, *, chunk_id: UUID | None = None) -> KnowledgeChunk:
    return KnowledgeChunk(
        id=chunk_id or uuid4(),
        document_version_id=uuid4(),
        ordinal=0,
        heading_path=("Runbook",),
        page_number=1,
        structural_location=None,
        text=text,
        token_count=max(1, len(text.split())),
        content_sha256=sha256(text.encode()).hexdigest(),
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags=("soc",),
        chunking_mode="rule",
        is_degraded=False,
    )


def fused(item: KnowledgeChunk, score: float) -> FusedRetrievalMatch:
    return FusedRetrievalMatch(
        chunk=item,
        fusion_score=score,
        bm25_score=2.0,
        vector_score=0.8,
        bm25_ranks=(1,),
        vector_ranks=(2,),
    )


def retrieval(*matches: FusedRetrievalMatch) -> HybridRetrievalResult:
    prior = RetrievalDegradation(
        kind=RetrievalDegradationKind.VECTOR_DEGRADED,
        error_category="embedding_unavailable",
        message="Vector unavailable.",
    )
    return HybridRetrievalResult("patch critical CVE", ("patch critical CVE",), matches, (prior,))


@dataclass
class FakeTransport:
    response: httpx.Response | Exception

    def __post_init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post(self, url, *, headers, json, timeout):
        self.calls.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def response(payload: object, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


def adapter(transport: FakeTransport, **changes) -> BgeRerankerV2M3Http:
    return BgeRerankerV2M3Http(
        endpoint="https://reranker.example/v1/rerank",
        api_key="secret",
        transport=transport,
        **changes,
    )


def valid_payload(scores: tuple[float, ...] = (0.2, 0.9), *, tokens: int = 12):
    return {
        "model": "bge-reranker-v2-m3",
        "data": [
            {"index": index, "relevance_score": score} for index, score in enumerate(scores)
        ],
        "usage": {"total_tokens": tokens},
    }


def test_http_adapter_sends_bounded_provider_neutral_request_and_records_cost() -> None:
    first, second = chunk("first document"), chunk("second document")
    transport = FakeTransport(response(valid_payload()))
    metrics = RerankerMetrics()
    client = adapter(
        transport,
        cost_per_million_tokens=2.0,
        max_request_cost=0.01,
        metrics=metrics,
    )

    result = client.rerank("  query  ", (first, second), model="bge-reranker-v2-m3")

    assert result == (RerankedMatch(first.id, 0.2), RerankedMatch(second.id, 0.9))
    sent = transport.calls[0]
    assert sent["json"] == {
        "model": "bge-reranker-v2-m3",
        "query": "query",
        "documents": ["first document", "second document"],
        "return_documents": False,
    }
    assert sent["headers"] == {"Authorization": "Bearer secret"}
    snapshot = metrics.snapshot()
    assert snapshot.calls == 1
    assert snapshot.documents == 2
    assert snapshot.input_tokens == 12
    assert snapshot.estimated_cost == pytest.approx(0.000024)
    assert snapshot.failures == 0


@pytest.mark.parametrize(
    ("query", "items", "model", "message"),
    [
        ("", (chunk("a"),), "bge-reranker-v2-m3", "query"),
        ("too long", (chunk("a"),), "bge-reranker-v2-m3", "query"),
        ("q", (), "bge-reranker-v2-m3", "chunks"),
        ("q", (chunk("a"),), "", "model"),
    ],
)
def test_http_adapter_rejects_request_bounds_before_network(query, items, model, message) -> None:
    transport = FakeTransport(response(valid_payload((0.5,))))
    client = adapter(transport, max_query_characters=4, max_total_characters=20)

    with pytest.raises(ValueError, match=message):
        client.rerank(query, items, model=model)

    assert transport.calls == []


def test_http_adapter_rejects_duplicate_chunks_and_total_text_bound() -> None:
    item = chunk("123456")
    transport = FakeTransport(response(valid_payload((0.5,))))
    client = adapter(
        transport,
        max_query_characters=3,
        max_text_characters=6,
        max_total_characters=8,
    )
    with pytest.raises(ValueError, match="duplicate"):
        client.rerank("q", (item, item), model="bge-reranker-v2-m3")
    with pytest.raises(ValueError, match="max_total"):
        client.rerank("qqq", (item,), model="bge-reranker-v2-m3")
    assert transport.calls == []


@pytest.mark.parametrize(
        "payload",
    [
        {"model": "wrong", "data": [], "usage": {"total_tokens": 1}},
        {
            "model": "bge-reranker-v2-m3",
            "data": [{"index": 0, "score": 0.5}, {"index": 0, "score": 0.4}],
            "usage": {"total_tokens": 1},
        },
        {
            "model": "bge-reranker-v2-m3",
            "data": [{"index": 0, "score": 1.1}, {"index": 1, "score": 0.4}],
            "usage": {"total_tokens": 1},
        },
        {
            "model": "bge-reranker-v2-m3",
            "data": [{"index": 0, "score": 0.5}, {"index": 1, "score": 0.4}],
        },
    ],
)
def test_http_adapter_rejects_malformed_model_indices_scores_and_usage(payload) -> None:
    client = adapter(FakeTransport(response(payload)))

    with pytest.raises(RerankerResponseError, match="invalid reranker response"):
        client.rerank("q", (chunk("a"), chunk("b")), model="bge-reranker-v2-m3")

    assert client.metrics.snapshot().failures == 1


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, RerankerAuthenticationError),
        (403, RerankerAuthenticationError),
        (429, RerankerRateLimitError),
        (503, RerankerUnavailableError),
        (400, RerankerResponseError),
    ],
)
def test_http_adapter_classifies_provider_status(status, error) -> None:
    client = adapter(FakeTransport(response({"error": "sensitive provider detail"}, status)))

    with pytest.raises(error) as caught:
        client.rerank("q", (chunk("a"),), model="bge-reranker-v2-m3")

    assert "sensitive" not in str(caught.value)
    assert client.metrics.snapshot().failures == 1


def test_http_adapter_maps_transport_error_and_enforces_response_size() -> None:
    request = httpx.Request("POST", "https://reranker.example")
    unavailable = adapter(FakeTransport(httpx.ReadTimeout("slow", request=request)))
    with pytest.raises(RerankerUnavailableError):
        unavailable.rerank("q", (chunk("a"),), model="bge-reranker-v2-m3")

    oversized = adapter(FakeTransport(response(valid_payload((0.5,)))), max_response_bytes=5)
    with pytest.raises(RerankerResponseError, match="size"):
        oversized.rerank("q", (chunk("a"),), model="bge-reranker-v2-m3")


@pytest.mark.parametrize(
    ("tokens", "changes", "message"),
    [
        (11, {"max_billable_tokens": 10}, "token usage"),
        (
            10,
            {"cost_per_million_tokens": 1_000_000, "max_request_cost": 9},
            "cost",
        ),
    ],
)
def test_http_adapter_enforces_token_and_cost_ceiling(tokens, changes, message) -> None:
    client = adapter(FakeTransport(response(valid_payload((0.5,), tokens=tokens))), **changes)

    with pytest.raises(RerankerResponseError, match=message):
        client.rerank("q", (chunk("a"),), model="bge-reranker-v2-m3")
    snapshot = client.metrics.snapshot()
    assert snapshot.input_tokens == tokens
    assert snapshot.failures == 1


@dataclass
class FakeReranker:
    scores: object = ()
    error: Exception | None = None

    def rerank(self, query, chunks, *, model):
        if self.error:
            raise self.error
        return self.scores


def test_service_stably_sorts_cross_encoder_scores_and_preserves_fusion_evidence() -> None:
    first, second, third = chunk("first"), chunk("second"), chunk("third")
    source = retrieval(fused(first, 0.05), fused(second, 0.04), fused(third, 0.03))
    reranker = FakeReranker(
        (
            RerankedMatch(third.id, 0.8),
            RerankedMatch(first.id, 0.8),
            RerankedMatch(second.id, 0.9),
        )
    )

    result = RerankingService(reranker).rerank(source)

    assert [match.chunk.id for match in result.matches] == [second.id, first.id, third.id]
    assert [match.reranker_score for match in result.matches] == [0.9, 0.8, 0.8]
    assert [match.fusion_score for match in result.matches] == [0.04, 0.05, 0.03]
    assert result.degradations == source.degradations


@pytest.mark.parametrize(
    "reranker",
    [
        FakeReranker(error=RerankerUnavailableError("down")),
        FakeReranker((RerankedMatch(uuid4(), 0.5),)),
        FakeReranker("malformed"),
    ],
)
def test_service_degrades_without_fake_scores_and_preserves_fused_order(reranker) -> None:
    first, second = chunk("first"), chunk("second")
    source = retrieval(fused(first, 0.05), fused(second, 0.04))

    result = RerankingService(reranker).rerank(source)

    assert [match.chunk.id for match in result.matches] == [first.id, second.id]
    assert [match.reranker_score for match in result.matches] == [None, None]
    assert result.degradations[:-1] == source.degradations
    assert result.degradations[-1].kind is RetrievalDegradationKind.RERANKER_DEGRADED


def test_service_uses_response_category_and_handles_empty_results_without_call() -> None:
    source = retrieval()
    reranker = FakeReranker(error=AssertionError("must not call"))
    empty = RerankingService(reranker).rerank(source)
    assert empty.matches == ()
    assert empty.degradations == source.degradations

    item = chunk("first")
    degraded = RerankingService(
        FakeReranker(error=RerankerResponseError("bad"))
    ).rerank(retrieval(fused(item, 0.05)))
    assert degraded.degradations[-1].error_category == "reranker_response"


def test_service_rejects_unbounded_input_before_provider_call() -> None:
    item = chunk("123456")
    fake = FakeReranker((RerankedMatch(item.id, 0.5),))
    service = RerankingService(fake, max_query_characters=4, max_total_characters=10)
    with pytest.raises(ValueError, match="original_query"):
        service.rerank(
            HybridRetrievalResult("too long", ("too long",), (fused(item, 0.1),), ())
        )
