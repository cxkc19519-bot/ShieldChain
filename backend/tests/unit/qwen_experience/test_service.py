from __future__ import annotations

import asyncio

from shieldchain.core.config import Settings
from shieldchain.llm.ports import ChatResponse
from shieldchain.qwen_experience import service as service_module
from shieldchain.qwen_experience.schemas import QwenExperienceChatRequest
from shieldchain.qwen_experience.service import QwenExperienceService
from shieldchain.qwen_experience.web_search import BingSearchResult


class FakeLlm:
    responses: list[ChatResponse] = []
    requests = []

    def __init__(self, settings, client) -> None:
        del settings, client

    async def chat(self, request):
        self.requests.append(request)
        return self.responses.pop(0)


class FakeSearch:
    def __init__(self) -> None:
        self.queries: list[str] = []

    async def search(self, query: str, *, limit: int = 5):
        self.queries.append(query)
        assert limit == 5
        return (
            BingSearchResult(
                title="官方安全公告",
                url="https://example.com/security",
                snippet="这是最新公开说明。",
            ),
        )


def test_model_can_choose_one_bing_search_before_answer(monkeypatch) -> None:
    FakeLlm.requests = []
    FakeLlm.responses = [
        ChatResponse(
            content='{"action":"search","query":"最新 CVE 安全公告"}',
            model="shieldchain-qwen3-30b",
            prompt_tokens=10,
            completion_tokens=5,
        ),
        ChatResponse(
            content="根据联网结果，当前公告如下。[1]",
            model="shieldchain-qwen3-30b",
            prompt_tokens=30,
            completion_tokens=12,
        ),
    ]
    monkeypatch.setattr(service_module, "DeepSeekClient", FakeLlm)
    search = FakeSearch()
    service = QwenExperienceService(Settings(_env_file=None), web_search=search)

    response = asyncio.run(
        service.chat(
            QwenExperienceChatRequest(messages=[{"role": "user", "content": "搜索最新漏洞公告"}])
        )
    )

    assert search.queries == ["最新 CVE 安全公告"]
    assert len(FakeLlm.requests) == 2
    assert "不可信公开网页摘要" in FakeLlm.requests[1].messages[1].content
    assert "联网来源" in response.content
    assert "https://example.com/security" in response.content
    assert response.prompt_tokens == 45


def test_model_can_answer_without_search(monkeypatch) -> None:
    FakeLlm.requests = []
    FakeLlm.responses = [
        ChatResponse(
            content='{"action":"answer"}',
            model="shieldchain-qwen3-30b",
            prompt_tokens=8,
            completion_tokens=3,
        ),
        ChatResponse(
            content="零信任要求持续验证。",
            model="shieldchain-qwen3-30b",
            prompt_tokens=18,
            completion_tokens=7,
        ),
    ]
    monkeypatch.setattr(service_module, "DeepSeekClient", FakeLlm)
    search = FakeSearch()
    service = QwenExperienceService(Settings(_env_file=None), web_search=search)

    response = asyncio.run(
        service.chat(
            QwenExperienceChatRequest(messages=[{"role": "user", "content": "解释零信任"}])
        )
    )

    assert search.queries == []
    assert response.content == "零信任要求持续验证。"
    assert len(FakeLlm.requests) == 2
