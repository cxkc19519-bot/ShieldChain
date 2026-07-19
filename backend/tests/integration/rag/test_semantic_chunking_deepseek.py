from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

from shieldchain.core.config import Settings
from shieldchain.core.logging import configure_logging
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.rag.chunking import DeterministicChunker
from shieldchain.rag.domain import SensitivityLevel
from shieldchain.rag.ports import ParsedContent, ParsedElement
from shieldchain.rag.semantic_chunking import DeepSeekSemanticChunker, SemanticChunkingPolicy


def settings() -> Settings:
    return Settings(
        environment="test",
        deepseek_base_url="https://llm.invalid/v1/",
        deepseek_model="deepseek-mocked",
        deepseek_api_key="not-a-real-key",
    )


def candidates():
    version_id = uuid4()
    parsed = ParsedContent(
        text="contain endpoint. preserve evidence.",
        media_type="text/plain",
        metadata={"title": "Runbook"},
        elements=(
            ParsedElement("paragraph", "contain endpoint. ", "line:1"),
            ParsedElement("paragraph", "preserve evidence.", "line:2"),
        ),
    )
    return version_id, DeterministicChunker().chunk(
        parsed,
        document_version_id=version_id,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"soc"},
    )


@pytest.mark.asyncio
async def test_mocked_deepseek_adapter_optimizes_without_network() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": '{"boundaries":[{"start":0,"end":2}]}'}}
                ],
                "model": "deepseek-mocked",
                "usage": {"prompt_tokens": 20, "completion_tokens": 8},
            },
        )

    version_id, rule = candidates()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = DeepSeekClient(settings(), http_client)
        result = await DeepSeekSemanticChunker(
            client,
            policy=SemanticChunkingPolicy(model="deepseek-mocked"),
        ).optimize(rule, document_version_id=version_id)

    assert result.audit.outcome == "semantic"
    assert result.items[0].chunk.text == "contain endpoint. preserve evidence."
    assert len(requests) == 1
    outgoing = json.loads(requests[0].content)
    assert outgoing["temperature"] == 0.0
    assert outgoing["stream"] is False


@pytest.mark.asyncio
async def test_mocked_deepseek_malformed_boundary_json_falls_back() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "not-json"}}],
                "model": "deepseek-mocked",
                "usage": {"prompt_tokens": 10, "completion_tokens": 1},
            },
        )

    version_id, rule = candidates()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        result = await DeepSeekSemanticChunker(
            DeepSeekClient(settings(), http_client)
        ).optimize(rule, document_version_id=version_id)

    assert result.audit.outcome == "rule_degraded"
    assert result.audit.failure_category == "malformed_json"
    assert [item.chunk.text for item in result.items] == [
        "contain endpoint. ",
        "preserve evidence.",
    ]


@pytest.mark.asyncio
async def test_mocked_network_failure_retries_then_degrades_without_leaking_detail(
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempts = 0
    configure_logging("test")

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("sensitive-dns-host.internal", request=request)

    async def no_sleep(_seconds: float) -> None:
        return None

    version_id, rule = candidates()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        result = await DeepSeekSemanticChunker(
            DeepSeekClient(settings(), http_client, sleep=no_sleep)
        ).optimize(rule, document_version_id=version_id)

    assert attempts == 3
    assert result.audit.outcome == "rule_degraded"
    assert result.audit.failure_category == "unavailable"
    assert result.audit.failure_detail is None
    assert "sensitive-dns-host" not in repr(result.audit)
    logs = capsys.readouterr().out
    assert "network_error" in logs
    assert "sensitive-dns-host" not in logs
