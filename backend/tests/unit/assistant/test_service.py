from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from shieldchain.assistant.schemas import AssistantChatRequest
from shieldchain.assistant.service import GroundedAssistantService
from shieldchain.assistant.store import LocalConversationStore


class StableTitleAssistant(GroundedAssistantService):
    def __init__(self, store: LocalConversationStore) -> None:
        super().__init__(
            object(),
            object(),
            settings=object(),
            tenant_id=uuid4(),
            principal_id=uuid4(),
            store=store,
        )
        self.summary_calls = 0

    def sync_historical_reports(self) -> int:
        return 0

    def _retrieve(self, query: str):
        del query
        return []

    async def _summarize_with_deepseek(self, question: str, answer: str) -> str:
        del question, answer
        self.summary_calls += 1
        return f"稳定标题{self.summary_calls}"


def test_sidebar_title_is_generated_only_for_the_first_turn(tmp_path) -> None:
    store = LocalConversationStore(tmp_path)
    service = StableTitleAssistant(store)

    first = asyncio.run(service.chat(AssistantChatRequest(message="第一个问题")))
    conversation_id = UUID(str(first.conversation_id))
    assert store.get(conversation_id)["summary"] == "稳定标题1"

    asyncio.run(
        service.chat(AssistantChatRequest(message="第二个问题", conversation_id=conversation_id))
    )

    assert service.summary_calls == 1
    assert store.get(conversation_id)["summary"] == "稳定标题1"


def test_manual_rename_replaces_the_generated_sidebar_title(tmp_path) -> None:
    store = LocalConversationStore(tmp_path)
    conversation = store.create("原始问题")
    conversation_id = UUID(str(conversation["id"]))
    store.set_summary(conversation_id, "模型生成标题")

    renamed = store.rename(conversation_id, "用户指定标题")

    assert renamed["title"] == "用户指定标题"
    assert renamed["summary"] == "用户指定标题"


class ConversationalAssistant(StableTitleAssistant):
    def __init__(self, store: LocalConversationStore) -> None:
        super().__init__(store)
        self.conversational_calls = 0
        self.retrieval_calls = 0

    def _retrieve(self, query: str):
        del query
        self.retrieval_calls += 1
        return []

    async def _answer_conversationally(self, message, history, memory_summary):
        del history, memory_summary
        self.conversational_calls += 1
        return f"自然回应：{message}", "local-qwen"


def test_greeting_uses_model_conversation_without_rag_rejection(tmp_path) -> None:
    store = LocalConversationStore(tmp_path)
    service = ConversationalAssistant(store)

    response = asyncio.run(service.chat(AssistantChatRequest(message="你好！")))

    assert response.answer == "自然回应：你好！"
    assert response.model == "local-qwen"
    assert response.citations == []
    assert service.conversational_calls == 1
    assert service.retrieval_calls == 0


def test_greeting_with_security_question_still_uses_grounded_retrieval(tmp_path) -> None:
    store = LocalConversationStore(tmp_path)
    service = ConversationalAssistant(store)

    response = asyncio.run(
        service.chat(AssistantChatRequest(message="你好，请帮我分析这条安全告警"))
    )

    assert "知识库或历史调查报告中找到足够依据" in response.answer
    assert service.conversational_calls == 0
    assert service.retrieval_calls == 1
