from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import FrozenInstanceError
from typing import Any, cast

import httpx
import pytest

from shieldchain.core.config import Settings
from shieldchain.core.logging import configure_logging
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    LlmAuthenticationError,
    LlmRateLimitError,
    LlmResponseError,
    LlmUnavailableError,
)

Sleep = Callable[[float], Awaitable[None]]


def settings() -> Settings:
    return Settings(
        environment="test",
        deepseek_base_url="https://llm.example.test/v1/",
        deepseek_model="deepseek-test",
        deepseek_api_key="unit-test-key",
    )


def success_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": "world"}}],
            "model": "deepseek-test",
            "usage": {"prompt_tokens": 3, "completion_tokens": 1},
        },
    )


def request() -> ChatRequest:
    return ChatRequest(
        messages=(
            ChatMessage(role="system", content="system instruction"),
            ChatMessage(role="user", content="sensitive prompt"),
        ),
        temperature=0.25,
        max_tokens=77,
    )


def client_for(
    handler: Callable[[httpx.Request], httpx.Response], sleep: Sleep | None = None
) -> tuple[DeepSeekClient, httpx.AsyncClient]:
    configure_logging("test")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    kwargs: dict[str, Any] = {}
    if sleep is not None:
        kwargs["sleep"] = sleep
    return DeepSeekClient(settings(), http_client, **kwargs), http_client


@pytest.mark.asyncio
async def test_chat_sends_contract_and_maps_success() -> None:
    captured: list[httpx.Request] = []

    def handler(outgoing: httpx.Request) -> httpx.Response:
        captured.append(outgoing)
        return success_response()

    client, http_client = client_for(handler)
    async with http_client:
        response = await client.chat(request())

    assert response == ChatResponse(
        content="world",
        model="deepseek-test",
        prompt_tokens=3,
        completion_tokens=1,
    )
    assert len(captured) == 1
    outgoing = captured[0]
    assert outgoing.method == "POST"
    assert outgoing.url == httpx.URL("https://llm.example.test/v1/chat/completions")
    assert outgoing.headers["Authorization"] == "Bearer unit-test-key"
    assert outgoing.headers["Content-Type"] == "application/json"
    assert outgoing.extensions["timeout"] == {
        "connect": 30.0,
        "read": 30.0,
        "write": 30.0,
        "pool": 30.0,
    }
    assert outgoing.read()
    assert __import__("json").loads(outgoing.content) == {
        "model": "deepseek-test",
        "messages": [
            {"role": "system", "content": "system instruction"},
            {"role": "user", "content": "sensitive prompt"},
        ],
        "temperature": 0.25,
        "max_tokens": 77,
        "stream": False,
    }


def test_transport_types_are_frozen() -> None:
    message = ChatMessage(role="user", content="hello")
    chat_request = ChatRequest(messages=(message,))
    response = ChatResponse("answer", "model", 1, 1)

    with pytest.raises(FrozenInstanceError):
        message.content = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        chat_request.max_tokens = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        response.content = "changed"  # type: ignore[misc]


def test_chat_request_normalizes_message_list_to_tuple() -> None:
    source = [ChatMessage(role="user", content="hello")]

    chat_request = ChatRequest(messages=cast(Any, source))

    assert isinstance(chat_request.messages, tuple)
    assert chat_request.messages == tuple(source)


def test_chat_request_does_not_retain_caller_message_list() -> None:
    message = ChatMessage(role="user", content="hello")
    source = [message]
    chat_request = ChatRequest(messages=cast(Any, source))

    source.clear()

    assert chat_request.messages == (message,)


@pytest.mark.parametrize(
    ("make_request", "message"),
    [
        (lambda: ChatRequest(messages=()), "at least one message"),
        (
            lambda: ChatRequest(messages=(ChatMessage(role="user", content=" "),)),
            "content must not be empty",
        ),
        (
            lambda: ChatRequest(
                messages=(
                    ChatMessage(
                        role=cast(Any, "tool"),
                        content="hello",
                    ),
                )
            ),
            "invalid role",
        ),
        (
            lambda: ChatRequest(
                messages=(ChatMessage(role="user", content="hello"),), temperature=-0.01
            ),
            "temperature",
        ),
        (
            lambda: ChatRequest(
                messages=(ChatMessage(role="user", content="hello"),), temperature=2.01
            ),
            "temperature",
        ),
        (
            lambda: ChatRequest(
                messages=(ChatMessage(role="user", content="hello"),), max_tokens=0
            ),
            "max_tokens",
        ),
        (
            lambda: ChatRequest(
                messages=(ChatMessage(role="user", content="hello"),), max_tokens=8193
            ),
            "max_tokens",
        ),
    ],
)
def test_invalid_requests_fail_before_http(
    make_request: Callable[[], ChatRequest], message: str
) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success_response()

    with pytest.raises(ValueError, match=message):
        make_request()

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 403])
async def test_authentication_errors_are_not_retried(status_code: int) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status_code)

    client, http_client = client_for(handler)
    async with http_client:
        with pytest.raises(LlmAuthenticationError):
            await client.chat(request())

    assert calls == 1


@pytest.mark.asyncio
async def test_rate_limit_retries_twice_then_raises() -> None:
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429)

    async def sleep(delay: float) -> None:
        delays.append(delay)

    client, http_client = client_for(handler, sleep)
    async with http_client:
        with pytest.raises(LlmRateLimitError):
            await client.chat(request())

    assert calls == 3
    assert delays == [0.5, 1.0]


@pytest.mark.asyncio
async def test_server_error_retries_then_recovers() -> None:
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500) if calls < 3 else success_response()

    async def sleep(delay: float) -> None:
        delays.append(delay)

    client, http_client = client_for(handler, sleep)
    async with http_client:
        response = await client.chat(request())

    assert response.content == "world"
    assert calls == 3
    assert delays == [0.5, 1.0]


@pytest.mark.asyncio
async def test_server_error_exhaustion_raises_unavailable() -> None:
    client, http_client = client_for(lambda _: httpx.Response(503), _no_sleep)
    async with http_client:
        with pytest.raises(LlmUnavailableError):
            await client.chat(request())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_type",
    [
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
    ],
)
async def test_timeout_retries_twice_then_raises(
    exception_type: type[httpx.TimeoutException],
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    delays: list[float] = []

    def handler(outgoing: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise exception_type("private timeout detail", request=outgoing)

    async def sleep(delay: float) -> None:
        delays.append(delay)

    client, http_client = client_for(handler, sleep)
    async with http_client:
        with pytest.raises(LlmUnavailableError):
            await client.chat(request())

    assert calls == 3
    assert delays == [0.5, 1.0]
    output = capsys.readouterr().out
    for forbidden in ("unit-test-key", "sensitive prompt", "private timeout detail"):
        assert forbidden not in output


@pytest.mark.asyncio
async def test_overall_deadline_cuts_off_retry_backoff_without_real_sleep(
    capsys: pytest.CaptureFixture[str],
) -> None:
    backoff_started = asyncio.Event()
    never_finishes = asyncio.Event()
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429)

    async def hanging_sleep(delay: float) -> None:
        delays.append(delay)
        backoff_started.set()
        await never_finishes.wait()

    async def expiring_deadline(
        operation: Awaitable[ChatResponse], timeout: float
    ) -> ChatResponse:
        assert timeout == 30.0
        task = asyncio.create_task(operation)
        await backoff_started.wait()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        raise TimeoutError

    configure_logging("test")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = DeepSeekClient(
        settings(),
        http_client,
        sleep=hanging_sleep,
        deadline=expiring_deadline,
    )
    async with http_client:
        with pytest.raises(LlmUnavailableError) as error:
            await client.chat(request())

    assert calls == 1
    assert delays == [0.5]
    assert str(error.value) == "LLM request deadline exceeded"
    output = capsys.readouterr().out
    for forbidden in ("unit-test-key", "sensitive prompt", "private response"):
        assert forbidden not in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "answer"}}],
                "model": "model",
                "usage": {"prompt_tokens": "3", "completion_tokens": 1},
            },
        ),
        httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "answer"}}],
                "model": "   ",
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            },
        ),
        httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "   "}}],
                "model": "model",
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            },
        ),
    ],
)
async def test_malformed_success_response_is_not_retried(response: httpx.Response) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return response

    client, http_client = client_for(handler)
    async with http_client:
        with pytest.raises(LlmResponseError):
            await client.chat(request())

    assert calls == 1


@pytest.mark.asyncio
async def test_other_client_error_is_response_error_without_retry() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400)

    client, http_client = client_for(handler)
    async with http_client:
        with pytest.raises(LlmResponseError):
            await client.chat(request())

    assert calls == 1


@pytest.mark.asyncio
async def test_logs_only_allowed_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("test")
    client, http_client = client_for(lambda _: success_response())
    async with http_client:
        await client.chat(request())

    output = capsys.readouterr().out
    assert "model=deepseek-test" in output
    assert "attempt=1" in output
    assert "status_category=success" in output
    assert "prompt_count=3" in output
    assert "completion_count=1" in output
    for forbidden in (
        "unit-test-key",
        "Authorization",
        "Bearer",
        "system instruction",
        "sensitive prompt",
        "world",
    ):
        assert forbidden not in output


async def _no_sleep(_: float) -> None:
    return None
