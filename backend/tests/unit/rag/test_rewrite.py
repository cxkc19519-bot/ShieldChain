from __future__ import annotations

import json

import pytest

from shieldchain.llm.ports import (
    ChatRequest,
    ChatResponse,
    LlmAuthenticationError,
    LlmRateLimitError,
    LlmResponseError,
    LlmUnavailableError,
)
from shieldchain.rag.rewrite import DeepSeekQueryRewriter, RewritePolicy


class StubLlm:
    def __init__(self, values: list[ChatResponse | Exception], model: str = "deepseek-test"):
        self.values = values
        self.model = model
        self.requests: list[ChatRequest] = []

    async def chat(self, request: ChatRequest) -> ChatResponse:
        self.requests.append(request)
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def response(content: str) -> ChatResponse:
    return ChatResponse(content, "deepseek-test", 20, 10)


def valid_payload() -> str:
    return json.dumps(
        {
            "normalized_query": "CVE-2024-1234 Log4j 漏洞排查",
            "resolved_query": "排查生产服务器上的 CVE-2024-1234 Log4j 漏洞",
            "security_entities": [
                {"type": "cve", "value": "CVE-2024-1234"},
                {"type": "product", "value": "Log4j"},
            ],
            "queries": [
                "CVE-2024-1234 Log4j remediation",
                "CVE-2024-1234 Log4j 漏洞排查",
            ],
        },
        ensure_ascii=False,
    )


@pytest.mark.asyncio
async def test_preserves_original_and_structures_context_entities_and_multi_query() -> None:
    client = StubLlm([response(valid_payload())])
    result = await DeepSeekQueryRewriter(client).rewrite(
        "它在生产上怎么排查？", context=("上文讨论 CVE-2024-1234 和 Log4j。",)
    )

    assert result.original_query == "它在生产上怎么排查？"
    assert result.normalized_query == "CVE-2024-1234 Log4j 漏洞排查"
    assert result.resolved_query == "排查生产服务器上的 CVE-2024-1234 Log4j 漏洞"
    assert result.queries == (
        "它在生产上怎么排查？",
        "CVE-2024-1234 Log4j 漏洞排查",
        "排查生产服务器上的 CVE-2024-1234 Log4j 漏洞",
        "CVE-2024-1234 Log4j remediation",
    )
    assert [(item.type, item.value) for item in result.security_entities] == [
        ("cve", "CVE-2024-1234"),
        ("product", "Log4j"),
    ]
    assert result.rewrite_degraded is False
    prompt = json.loads(client.requests[0].messages[1].content)
    assert prompt["original_query"] == "它在生产上怎么排查？"
    assert prompt["conversation_context"] == ["上文讨论 CVE-2024-1234 和 Log4j。"]
    assert "untrusted data" in client.requests[0].messages[0].content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "```json\n{}\n```",
        '{"normalized_query":"a","normalized_query":"b","resolved_query":"c",'
        '"security_entities":[],"queries":[]}',
        '{"normalized_query":NaN,"resolved_query":"c","security_entities":[],"queries":[]}',
        '{"normalized_query":"a","resolved_query":"b","security_entities":[],'
        '"queries":[],"extra":true}',
        '{"normalized_query":"a","resolved_query":"b","security_entities":{},"queries":[]}',
        '{"normalized_query":"a","resolved_query":"b","security_entities":'
        '[{"type":"secret","value":"x"}],"queries":[]}',
    ],
)
async def test_strict_json_or_schema_failure_degrades_to_original_only(payload: str) -> None:
    result = await DeepSeekQueryRewriter(StubLlm([response(payload)])).rewrite("original")

    assert result.queries == ("original",)
    assert result.normalized_query == "original"
    assert result.resolved_query == "original"
    assert result.security_entities == ()
    assert result.rewrite_degraded is True
    assert result.failure_category in {"malformed_json", "schema_error"}


@pytest.mark.asyncio
async def test_query_count_single_and_total_length_are_bounded() -> None:
    base = {
        "normalized_query": "a",
        "resolved_query": "b",
        "security_entities": [],
        "queries": ["c", "d"],
    }
    count = await DeepSeekQueryRewriter(
        StubLlm([response(json.dumps(base))]),
        policy=RewritePolicy(model="deepseek-test", max_generated_queries=1),
    ).rewrite("original")
    base["queries"] = ["toolong"]
    single = await DeepSeekQueryRewriter(
        StubLlm([response(json.dumps(base))]),
        policy=RewritePolicy(model="deepseek-test", max_query_chars=3),
    ).rewrite("original")
    base["queries"] = ["ccc"]
    total = await DeepSeekQueryRewriter(
        StubLlm([response(json.dumps(base))]),
        policy=RewritePolicy(model="deepseek-test", max_total_generated_chars=4),
    ).rewrite("original")

    assert count.failure_category == "query_limit"
    assert single.failure_category == "query_limit"
    assert total.failure_category == "query_limit"


@pytest.mark.asyncio
async def test_duplicate_queries_and_entities_are_removed_stably() -> None:
    payload = json.dumps(
        {
            "normalized_query": "ORIGINAL",
            "resolved_query": "resolved",
            "security_entities": [
                {"type": "product", "value": "Log4j"},
                {"type": "product", "value": "log4j"},
            ],
            "queries": ["resolved", "extra", "EXTRA"],
        }
    )
    result = await DeepSeekQueryRewriter(StubLlm([response(payload)])).rewrite("original")

    assert result.queries == ("original", "resolved", "extra")
    assert len(result.security_entities) == 1


@pytest.mark.asyncio
async def test_valid_model_expansions_are_bounded_without_degrading() -> None:
    payload = json.dumps(
        {
            "normalized_query": "normalized",
            "resolved_query": "resolved",
            "security_entities": [],
            "queries": ["one", "two", "three", "four", "five"],
        }
    )

    result = await DeepSeekQueryRewriter(StubLlm([response(payload)])).rewrite("original")

    assert result.rewrite_degraded is False
    assert result.failure_category is None
    assert result.queries == (
        "original",
        "normalized",
        "resolved",
        "one",
        "two",
        "three",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "category"),
    [
        (TimeoutError("secret endpoint"), "timeout"),
        (LlmRateLimitError("secret"), "rate_limit"),
        (LlmAuthenticationError("secret key"), "authentication"),
        (LlmUnavailableError("secret host"), "unavailable"),
        (LlmResponseError("secret body"), "response_error"),
        (RuntimeError("secret unexpected"), "internal_error"),
    ],
)
async def test_llm_failures_are_safely_classified_without_exception_text(
    error: Exception, category: str
) -> None:
    result = await DeepSeekQueryRewriter(StubLlm([error])).rewrite("original")

    assert result.queries == ("original",)
    assert result.rewrite_degraded is True
    assert result.failure_category == category
    assert "secret" not in repr(result)


@pytest.mark.asyncio
async def test_context_and_response_budgets_degrade_without_network_or_cost() -> None:
    no_call = StubLlm([response(valid_payload())])
    context_result = await DeepSeekQueryRewriter(
        no_call, policy=RewritePolicy(model="deepseek-test", max_context_chars=3)
    ).rewrite("original", context=("four",))
    response_result = await DeepSeekQueryRewriter(
        StubLlm([response(valid_payload())]),
        policy=RewritePolicy(model="deepseek-test", max_response_bytes=10),
    ).rewrite("original")

    assert context_result.failure_category == "context_limit"
    assert no_call.requests == []
    assert response_result.failure_category == "response_limit"


@pytest.mark.asyncio
async def test_blank_and_oversized_original_are_rejected_before_cloud_call() -> None:
    client = StubLlm([response(valid_payload())])
    rewriter = DeepSeekQueryRewriter(
        client, policy=RewritePolicy(model="deepseek-test", max_original_chars=3)
    )
    with pytest.raises(ValueError):
        await rewriter.rewrite(" ")
    with pytest.raises(ValueError):
        await rewriter.rewrite("four")
    assert client.requests == []


def test_policy_is_bounded_and_must_match_adapter_model() -> None:
    with pytest.raises(ValueError):
        RewritePolicy(max_generated_queries=0)
    with pytest.raises(ValueError, match="must match"):
        DeepSeekQueryRewriter(StubLlm([]), policy=RewritePolicy(model="different-model"))
