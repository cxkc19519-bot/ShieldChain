from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from time import perf_counter
from typing import Any

import httpx
import structlog

from shieldchain.core.config import Settings
from shieldchain.llm.ports import (
    ChatRequest,
    ChatResponse,
    LlmAuthenticationError,
    LlmRateLimitError,
    LlmResponseError,
    LlmUnavailableError,
)

type AsyncSleep = Callable[[float], Awaitable[None]]
type AsyncDeadline = Callable[[Awaitable[ChatResponse], float], Awaitable[ChatResponse]]
RETRY_DELAYS = (0.5, 1.0)
TOTAL_TIMEOUT_SECONDS = 30.0


class DeepSeekClient:
    def __init__(
        self,
        settings: Settings,
        http_client: httpx.AsyncClient,
        sleep: AsyncSleep = asyncio.sleep,
        deadline: AsyncDeadline = asyncio.wait_for,
    ) -> None:
        self._base_url = str(settings.deepseek_base_url).rstrip("/")
        self._model = settings.deepseek_model
        self._api_key = settings.deepseek_api_key.get_secret_value()
        self._http_client = http_client
        self._sleep = sleep
        self._deadline = deadline
        self._logger = structlog.get_logger(__name__)

    async def chat(self, request: ChatRequest) -> ChatResponse:
        try:
            return await self._deadline(
                self._chat_with_retries(request), TOTAL_TIMEOUT_SECONDS
            )
        except TimeoutError:
            raise LlmUnavailableError("LLM request deadline exceeded") from None

    async def _chat_with_retries(self, request: ChatRequest) -> ChatResponse:
        payload = {
            "model": self._model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": False,
        }

        for attempt in range(1, len(RETRY_DELAYS) + 2):
            started_at = perf_counter()
            try:
                response = await self._http_client.post(
                    f"{self._base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=httpx.Timeout(TOTAL_TIMEOUT_SECONDS),
                )
            except (httpx.ConnectTimeout, httpx.ReadTimeout):
                self._log_attempt(started_at, attempt, "timeout")
                if attempt > len(RETRY_DELAYS):
                    raise LlmUnavailableError("LLM request timed out") from None
                await self._sleep(RETRY_DELAYS[attempt - 1])
                continue

            status_category = _status_category(response.status_code)
            if response.status_code in {401, 403}:
                self._log_attempt(started_at, attempt, status_category)
                raise LlmAuthenticationError("LLM authentication failed")
            if response.status_code == 429:
                self._log_attempt(started_at, attempt, status_category)
                if attempt > len(RETRY_DELAYS):
                    raise LlmRateLimitError("LLM rate limit exceeded")
                await self._sleep(RETRY_DELAYS[attempt - 1])
                continue
            if 500 <= response.status_code <= 599:
                self._log_attempt(started_at, attempt, status_category)
                if attempt > len(RETRY_DELAYS):
                    raise LlmUnavailableError("LLM service unavailable")
                await self._sleep(RETRY_DELAYS[attempt - 1])
                continue
            if not 200 <= response.status_code <= 299:
                self._log_attempt(started_at, attempt, status_category)
                raise LlmResponseError("LLM request failed")

            chat_response = _parse_response(response)
            self._log_attempt(
                started_at,
                attempt,
                "success",
                prompt_tokens=chat_response.prompt_tokens,
                completion_tokens=chat_response.completion_tokens,
            )
            return chat_response

        raise AssertionError("bounded retry loop exhausted unexpectedly")

    def _log_attempt(
        self,
        started_at: float,
        attempt: int,
        status_category: str,
        *,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> None:
        fields: dict[str, object] = {
            "model": self._model,
            "attempt": attempt,
            "latency": round(perf_counter() - started_at, 6),
            "status_category": status_category,
        }
        if prompt_tokens is not None:
            fields["prompt_count"] = prompt_tokens
        if completion_tokens is not None:
            fields["completion_count"] = completion_tokens
        self._logger.info("llm_request", **fields)


def _status_category(status_code: int) -> str:
    if status_code in {401, 403}:
        return "authentication"
    if status_code == 429:
        return "rate_limit"
    if 500 <= status_code <= 599:
        return "server_error"
    if 400 <= status_code <= 499:
        return "client_error"
    return "success"


def _parse_response(response: httpx.Response) -> ChatResponse:
    try:
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        model = data["model"]
        usage = data["usage"]
        prompt_tokens = usage["prompt_tokens"]
        completion_tokens = usage["completion_tokens"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise LlmResponseError("LLM response was malformed") from None

    if not isinstance(content, str) or not isinstance(model, str):
        raise LlmResponseError("LLM response was malformed")
    if not _is_token_count(prompt_tokens) or not _is_token_count(completion_tokens):
        raise LlmResponseError("LLM response was malformed")

    return ChatResponse(
        content=content,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )


def _is_token_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
