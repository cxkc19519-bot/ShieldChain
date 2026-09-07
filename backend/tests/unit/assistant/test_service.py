from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime
from uuid import UUID, uuid4

from shieldchain.assistant.schemas import AssistantChatRequest
from shieldchain.assistant.service import (
    AssistantUnavailable,
    GroundedAssistantService,
    _AssistantEvidence,
)
from shieldchain.assistant.store import LocalConversationStore
from shieldchain.rag.schemas import RetrievalHitView


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
    assert response.grounding_status == "refused"
    assert response.refusal_reason == "insufficient_evidence"
    assert service.conversational_calls == 0
    assert service.retrieval_calls == 1


def _retrieval_hit() -> RetrievalHitView:
    return RetrievalHitView(
        chunk_id=uuid4(),
        knowledge_base_id=uuid4(),
        document_id=uuid4(),
        document_version_id=uuid4(),
        document_title="安全处置手册.md",
        excerpt="隔离前必须经过人工审批，并保留回滚方案。",
        heading_path=["处置边界"],
        page_number=3,
        structural_location="第 3 页",
        bm25_score=1.2,
        vector_score=0.8,
        fusion_score=0.9,
        reranker_score=0.85,
        updated_at=datetime(2026, 9, 3, tzinfo=UTC),
        integrity_sha256="a" * 64,
        verified_at=date(2026, 9, 2),
        review_due_at=date(2026, 10, 2),
        source_tiers=["primary_authority"],
        source_urls=["https://www.cac.gov.cn/example"],
    )


class EvidenceAssistant(StableTitleAssistant):
    def __init__(self, store: LocalConversationStore, *, generation_available: bool) -> None:
        super().__init__(store)
        self.hit = _retrieval_hit()
        self.generation_available = generation_available

    def _retrieve(self, query: str):
        del query
        return [self.hit]

    async def _answer_with_deepseek(self, message, history, memory_summary, citations):
        del message, history, memory_summary, citations
        if not self.generation_available:
            raise AssistantUnavailable("model unavailable")
        return "隔离操作必须先完成人工审批。", "local-qwen"


def test_grounded_answer_persists_full_citation_provenance(tmp_path) -> None:
    store = LocalConversationStore(tmp_path)
    service = EvidenceAssistant(store, generation_available=True)

    response = asyncio.run(service.chat(AssistantChatRequest(message="可以直接隔离吗？")))

    assert response.grounding_status == "grounded"
    assert response.refusal_reason is None
    assert response.model == "local-qwen"
    assert response.citations[0].document_version_id == service.hit.document_version_id
    assert response.citations[0].chunk_id == service.hit.chunk_id
    assert response.citations[0].page_number == 3
    assert response.citations[0].integrity_sha256 == "a" * 64
    assert response.citations[0].verified_at == date(2026, 9, 2)
    assert response.citations[0].review_due_at == date(2026, 10, 2)
    assert response.citations[0].source_tiers == ["primary_authority"]
    messages = LocalConversationStore.messages(store.get(response.conversation_id))
    assert messages[-1].grounding_status == "grounded"
    assert messages[-1].citations[0].chunk_id == service.hit.chunk_id


def test_generation_failure_returns_auditable_extractive_evidence(tmp_path) -> None:
    store = LocalConversationStore(tmp_path)
    service = EvidenceAssistant(store, generation_available=False)

    response = asyncio.run(service.chat(AssistantChatRequest(message="可以直接隔离吗？")))

    assert response.grounding_status == "extractive_degraded"
    assert response.model is None
    assert service.hit.excerpt in response.answer
    assert "人工复核后再采取行动" in response.answer
    assert [(item.kind, item.error_category) for item in response.degradations] == [
        ("generation_degraded", "unavailable")
    ]


class ConflictAssistant(EvidenceAssistant):
    def _retrieve(self, query: str):
        del query
        counter = self.hit.model_copy(
            update={
                "chunk_id": uuid4(),
                "document_id": uuid4(),
                "document_version_id": uuid4(),
                "document_title": "反证.md",
                "excerpt": "受控事件禁止自动隔离。",
            }
        )
        return _AssistantEvidence(
            hits=(self.hit, counter),
            refusal_reason="conflicting_evidence",
            degradations=(),
        )


def test_conflicting_evidence_is_refused_but_kept_for_human_review(tmp_path) -> None:
    service = ConflictAssistant(
        LocalConversationStore(tmp_path), generation_available=True
    )

    response = asyncio.run(service.chat(AssistantChatRequest(message="是否自动隔离？")))

    assert response.grounding_status == "refused"
    assert response.refusal_reason == "conflicting_evidence"
    assert "相互冲突" in response.answer
    assert len(response.citations) == 2
    assert response.model is None
