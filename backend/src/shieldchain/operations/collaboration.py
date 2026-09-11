"""Bounded real-data collaboration team for security operations reports."""

# ruff: noqa: E501
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import UUID

import httpx

from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError
from shieldchain.rag.api_service import KnowledgeApiService
from shieldchain.rag.schemas import RetrievalRequest

from .schemas import AgentRoleRunView, McpToolCallView


@dataclass(frozen=True)
class RoleDefinition:
    key: str
    label: str
    responsibility: str


_ROLES = (
    RoleDefinition("superagent", "总控智能体", "编排任务、明确当前风险焦点和交接顺序。"),
    RoleDefinition("alert_triage", "告警分诊智能体", "依据事件与告警工具结果进行分级、去重和优先级排序。"),
    RoleDefinition("threat_investigation", "威胁研判智能体", "关联漏洞线索、告警证据和攻击迹象，明确待证实事项。"),
    RoleDefinition("knowledge_retrieval", "知识检索智能体", "从本地知识库检索与当前告警相关的规范、技战术和处置依据。"),
    RoleDefinition("response_planning", "响应规划智能体", "仅提出需人工确认的处置建议，禁止调用或暗示执行命令。"),
    RoleDefinition("verification", "验证智能体", "说明建议实施后应检查的日志、指标和验收条件，不宣称已完成处置。"),
    RoleDefinition("reporting", "报告智能体", "汇总已确认事实、线索、局限性和建议，形成面向人工复核的结论。"),
)


class RealDataAgentTeam:
    def __init__(self, settings: Settings, knowledge: KnowledgeApiService, *, tenant_id: UUID, principal_id: UUID) -> None:
        self._settings = settings
        self._knowledge = knowledge
        self._tenant_id = tenant_id
        self._principal_id = principal_id

    async def run(self, tool_calls: list[McpToolCallView]) -> tuple[list[AgentRoleRunView], str | None]:
        facts = self._facts(tool_calls)
        knowledge = await asyncio.to_thread(self._retrieve, facts)
        results: list[AgentRoleRunView] = []
        handoff = "尚无前序结论。"
        model: str | None = None
        for definition in _ROLES:
            role_facts = facts + (f"\n知识检索依据：{knowledge}" if definition.key == "knowledge_retrieval" else "")
            summary, used_model = await self._ask(definition, role_facts, handoff)
            model = model or used_model
            results.append(AgentRoleRunView(
                role=definition.key,
                label=definition.label,
                status="completed" if used_model else "fallback",
                summary=summary,
                handoff_to=(_ROLES[len(results)].label if len(results) < len(_ROLES) else None),
            ))
            handoff = summary
        return results, model

    @staticmethod
    def _facts(tool_calls: list[McpToolCallView]) -> str:
        return "\n".join(f"{item.label}：{item.summary}\n" + "\n".join(item.items[:8]) for item in tool_calls)[:9000]

    def _retrieve(self, facts: str) -> str:
        try:
            bases = self._knowledge.list_knowledge_bases(tenant_id=self._tenant_id)
            if not bases:
                return "本地知识库为空，无法补充检索依据。"
            response = self._knowledge.retrieve(
                RetrievalRequest(query=facts[:2000], knowledge_base_ids=[item.id for item in bases], limit=3),
                tenant_id=self._tenant_id, principal_id=self._principal_id,
            )
            return response.answer[:1600] if response.answer else "未检索到可引用片段。"
        except Exception:
            return "知识库暂不可用；不得据此扩写事实。"

    async def _ask(self, definition: RoleDefinition, facts: str, handoff: str) -> tuple[str, str | None]:
        fallback = f"{definition.label}：基于已接入的只读数据进行人工复核建议；当前不能确认未在工具结果中出现的事实。"
        if not self._settings.deepseek_api_key.get_secret_value():
            return fallback, None
        prompt = (
            f"你是{definition.label}，职责是：{definition.responsibility}。仅依据以下受控工具结果和交接摘要，用中文输出不超过180字的公开摘要。"
            "不得编造事实、资产、漏洞影响、工具执行、命令、凭据或思维链；所有处置只能建议人工确认。\n"
            f"工具结果：\n{facts}\n前序交接：\n{handoff[:1200]}"
        )
        try:
            async with httpx.AsyncClient() as client:
                response = await DeepSeekClient(self._settings, client).chat(ChatRequest(
                    messages=(ChatMessage(role="system", content="你是受控安全多智能体中的一个专业角色。只输出公开中文摘要。"), ChatMessage(role="user", content=prompt)),
                    temperature=0.1, max_tokens=300,
                ))
            return " ".join(response.content.replace("**", "").split())[:800], response.model
        except LlmError:
            return fallback, None
