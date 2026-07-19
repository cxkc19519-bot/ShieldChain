from __future__ import annotations

from typing import Any

import httpx
import pytest

from shieldchain.rag.embedding import BgeM3HttpEmbedding
from shieldchain.rag.ports import (
    EmbeddingAuthenticationError,
    EmbeddingRateLimitError,
    EmbeddingResponseError,
    EmbeddingUnavailableError,
)


class FakeTransport:
    def __init__(self, response: httpx.Response | Exception) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        self.calls.append({"url": url, **kwargs})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def response(status: int, payload: object) -> httpx.Response:
    return httpx.Response(status, json=payload)


def adapter(transport: FakeTransport, **kwargs: Any) -> BgeM3HttpEmbedding:
    return BgeM3HttpEmbedding(
        endpoint="https://embedding.example/v1/embeddings",
        api_key="secret",
        transport=transport,
        expected_dimension=3,
        cost_per_million_tokens=2.0,
        **kwargs,
    )


def test_embed_validates_and_reorders_provider_result_and_records_usage() -> None:
    transport = FakeTransport(
        response(
            200,
            {
                "data": [
                    {"index": 1, "embedding": [0.4, 0.5, 0.6]},
                    {"index": 0, "embedding": [0.1, 0.2, 0.3]},
                ],
                "usage": {"total_tokens": 25},
            },
        )
    )
    subject = adapter(transport)

    assert subject.embed(["你好", "incident"], model="BAAI/bge-m3") == (
        (0.1, 0.2, 0.3),
        (0.4, 0.5, 0.6),
    )
    call = transport.calls[0]
    assert call["headers"] == {"Authorization": "Bearer secret"}
    assert call["json"] == {"model": "BAAI/bge-m3", "input": ["你好", "incident"]}
    metrics = subject.metrics.snapshot()
    assert (metrics.calls, metrics.texts, metrics.input_characters, metrics.input_tokens) == (
        1,
        2,
        10,
        25,
    )
    assert metrics.estimated_cost == pytest.approx(0.00005)
    assert metrics.failures == 0


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, EmbeddingAuthenticationError),
        (403, EmbeddingAuthenticationError),
        (429, EmbeddingRateLimitError),
        (503, EmbeddingUnavailableError),
        (400, EmbeddingResponseError),
    ],
)
def test_embed_classifies_http_failures(status: int, expected: type[Exception]) -> None:
    subject = adapter(FakeTransport(response(status, {"error": "redacted"})))

    with pytest.raises(expected):
        subject.embed(["text"], model="BAAI/bge-m3")

    assert subject.metrics.snapshot().failures == 1


def test_embed_classifies_timeout_without_leaking_transport_error() -> None:
    request = httpx.Request("POST", "https://embedding.example")
    subject = adapter(FakeTransport(httpx.ReadTimeout("secret upstream detail", request=request)))

    with pytest.raises(EmbeddingUnavailableError, match="unavailable"):
        subject.embed(["text"], model="BAAI/bge-m3")


def test_embed_classifies_protocol_errors_and_bounds_response_size() -> None:
    request = httpx.Request("POST", "https://embedding.example")
    protocol = adapter(FakeTransport(httpx.RemoteProtocolError("secret", request=request)))
    with pytest.raises(EmbeddingUnavailableError, match="unavailable"):
        protocol.embed(["text"], model="BAAI/bge-m3")
    oversized = adapter(
        FakeTransport(response(200, {"data": [], "usage": {"total_tokens": 0}})),
        max_response_bytes=2,
    )
    with pytest.raises(EmbeddingResponseError, match="size"):
        oversized.embed(["text"], model="BAAI/bge-m3")


@pytest.mark.parametrize(
    "payload",
    [
        {"data": [{"index": 0, "embedding": [0.1, 0.2]}]},
        {"data": [{"index": 0, "embedding": [0.1, "NaN", 0.3]}]},
        {"data": []},
        {"data": [{"index": 1, "embedding": [0.1, 0.2, 0.3]}]},
        {"data": [{"index": 0, "embedding": [0.1, 0.2, 0.3]}], "usage": {"total_tokens": -1}},
    ],
)
def test_embed_rejects_malformed_provider_responses(payload: object) -> None:
    subject = adapter(FakeTransport(response(200, payload)))

    with pytest.raises(EmbeddingResponseError):
        subject.embed(["text"], model="BAAI/bge-m3")


def test_embed_rejects_non_finite_embedding_values() -> None:
    raw = httpx.Response(
        200,
        content=b'{"data":[{"index":0,"embedding":[0.1,NaN,0.3]}]}',
        headers={"content-type": "application/json"},
    )
    subject = adapter(FakeTransport(raw))

    with pytest.raises(EmbeddingResponseError):
        subject.embed(["text"], model="BAAI/bge-m3")


@pytest.mark.parametrize(
    "texts",
    [[], [""], ["12345"], ["abc", "def"]],
)
def test_embed_enforces_batch_and_character_budgets_without_network(texts: list[str]) -> None:
    transport = FakeTransport(response(200, {}))
    subject = adapter(
        transport,
        max_batch_size=1,
        max_text_characters=4,
        max_batch_characters=4,
    )

    with pytest.raises(ValueError):
        subject.embed(texts, model="BAAI/bge-m3")

    assert transport.calls == []
