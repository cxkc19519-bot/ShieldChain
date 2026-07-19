from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import Lock
from typing import Any, Protocol

import httpx

from shieldchain.rag.ports import (
    EmbeddingAuthenticationError,
    EmbeddingRateLimitError,
    EmbeddingResponseError,
    EmbeddingUnavailableError,
)


class HttpTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object],
        timeout: float,
    ) -> httpx.Response: ...


@dataclass(frozen=True, slots=True)
class EmbeddingMetricsSnapshot:
    calls: int
    texts: int
    input_characters: int
    input_tokens: int
    estimated_cost: float
    failures: int


class EmbeddingMetrics:
    """Small thread-safe counter boundary; applications may scrape snapshots."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._values = [0, 0, 0, 0, 0.0, 0]

    def record(
        self, *, texts: int, characters: int, tokens: int, cost: float, failed: bool
    ) -> None:
        with self._lock:
            self._values[0] += 1
            self._values[1] += texts
            self._values[2] += characters
            self._values[3] += tokens
            self._values[4] += cost
            self._values[5] += int(failed)

    def snapshot(self) -> EmbeddingMetricsSnapshot:
        with self._lock:
            return EmbeddingMetricsSnapshot(*self._values)


class BgeM3HttpEmbedding:
    """Provider-neutral OpenAI-compatible HTTP adapter for BGE-M3 embeddings."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        transport: HttpTransport | None = None,
        timeout_seconds: float = 20.0,
        max_batch_size: int = 64,
        max_text_characters: int = 16_000,
        max_batch_characters: int = 128_000,
        expected_dimension: int = 1024,
        cost_per_million_tokens: float = 0.0,
        max_response_bytes: int = 8_000_000,
        metrics: EmbeddingMetrics | None = None,
    ) -> None:
        if not endpoint.startswith(("https://", "http://")):
            raise ValueError("endpoint must be an HTTP(S) URL")
        if not api_key.strip():
            raise ValueError("api_key must not be empty")
        for value, name in (
            (max_batch_size, "max_batch_size"),
            (max_text_characters, "max_text_characters"),
            (max_batch_characters, "max_batch_characters"),
            (expected_dimension, "expected_dimension"),
            (max_response_bytes, "max_response_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if not math.isfinite(cost_per_million_tokens) or cost_per_million_tokens < 0:
            raise ValueError("cost_per_million_tokens must be finite and non-negative")
        self._endpoint = endpoint
        self._api_key = api_key
        self._transport = transport or httpx.Client()
        self._timeout = timeout_seconds
        self._max_batch = max_batch_size
        self._max_text_chars = max_text_characters
        self._max_batch_chars = max_batch_characters
        self._dimension = expected_dimension
        self._cost_per_million = cost_per_million_tokens
        self._max_response_bytes = max_response_bytes
        self.metrics = metrics or EmbeddingMetrics()

    def embed(self, texts: Sequence[str], *, model: str) -> tuple[tuple[float, ...], ...]:
        copied = tuple(texts)
        if not copied or len(copied) > self._max_batch:
            raise ValueError(f"texts must contain between 1 and {self._max_batch} items")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must not be empty")
        if any(not isinstance(item, str) or not item.strip() for item in copied):
            raise ValueError("texts must contain non-empty strings")
        lengths = tuple(len(item) for item in copied)
        if any(length > self._max_text_chars for length in lengths):
            raise ValueError("a text exceeds max_text_characters")
        characters = sum(lengths)
        if characters > self._max_batch_chars:
            raise ValueError("texts exceed max_batch_characters")

        try:
            response = self._transport.post(
                self._endpoint,
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={"model": model, "input": list(copied)},
                timeout=self._timeout,
            )
            self._raise_for_status(response)
            if len(response.content) > self._max_response_bytes:
                raise EmbeddingResponseError("embedding response exceeds configured size")
            payload = response.json()
            vectors, tokens = self._parse(payload, expected_count=len(copied))
        except (
            EmbeddingAuthenticationError,
            EmbeddingRateLimitError,
            EmbeddingResponseError,
            EmbeddingUnavailableError,
        ):
            self.metrics.record(
                texts=len(copied), characters=characters, tokens=0, cost=0, failed=True
            )
            raise
        except httpx.TransportError as error:
            self.metrics.record(
                texts=len(copied), characters=characters, tokens=0, cost=0, failed=True
            )
            raise EmbeddingUnavailableError("embedding provider unavailable") from error
        except (ValueError, TypeError, KeyError) as error:
            self.metrics.record(
                texts=len(copied), characters=characters, tokens=0, cost=0, failed=True
            )
            raise EmbeddingResponseError("invalid embedding response") from error

        cost = tokens * self._cost_per_million / 1_000_000
        self.metrics.record(
            texts=len(copied), characters=characters, tokens=tokens, cost=cost, failed=False
        )
        return vectors

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        status = response.status_code
        if status in (401, 403):
            raise EmbeddingAuthenticationError("embedding authentication failed")
        if status == 429:
            raise EmbeddingRateLimitError("embedding rate limit exceeded")
        if status in (408, 425) or status >= 500:
            raise EmbeddingUnavailableError("embedding provider unavailable")
        if status >= 400:
            raise EmbeddingResponseError(f"embedding provider rejected request ({status})")

    def _parse(
        self, payload: Any, *, expected_count: int
    ) -> tuple[tuple[tuple[float, ...], ...], int]:
        if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), list):
            raise TypeError("data must be a list")
        data = payload["data"]
        if len(data) != expected_count:
            raise ValueError("embedding count mismatch")
        indexed: dict[int, tuple[float, ...]] = {}
        for position, item in enumerate(data):
            if not isinstance(item, Mapping):
                raise TypeError("embedding item must be an object")
            index = item.get("index", position)
            raw_vector = item.get("embedding")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index in indexed
            ):
                raise ValueError("invalid embedding index")
            if not isinstance(raw_vector, list) or len(raw_vector) != self._dimension:
                raise ValueError("embedding dimension mismatch")
            if any(
                not isinstance(value, int | float)
                or isinstance(value, bool)
                or not math.isfinite(value)
                for value in raw_vector
            ):
                raise ValueError("embedding values must be finite numbers")
            indexed[index] = tuple(float(value) for value in raw_vector)
        if set(indexed) != set(range(expected_count)):
            raise ValueError("embedding indices must be contiguous")
        usage = payload.get("usage")
        if not isinstance(usage, Mapping):
            raise TypeError("usage must be an object")
        tokens = usage.get("total_tokens", usage.get("prompt_tokens"))
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0:
            raise ValueError("token usage must be a non-negative integer")
        return tuple(indexed[index] for index in range(expected_count)), tokens
