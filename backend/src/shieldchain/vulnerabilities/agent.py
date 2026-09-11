from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError
from shieldchain.rag.api_service import KnowledgeApiService
from shieldchain.rag.schemas import RetrievalRequest

from .persistence import VulnerabilityFindingRow


class _AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    priority: str = Field(pattern=r"^(P0|P1|P2|P3)$")
    summary: str = Field(min_length=10, max_length=500)
    affected_assessment: str = Field(min_length=10, max_length=500)
    remediation: str = Field(min_length=10, max_length=500)
    verification: str = Field(min_length=10, max_length=500)
    evidence_gaps: list[str] = Field(max_length=8)


class _ActionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["remediate", "verify_not_affected"]
    tool_name: str = Field(min_length=3, max_length=128)
    verification_tool: str = Field(min_length=3, max_length=128)
    rationale: str = Field(min_length=10, max_length=500)
    success_criteria: str = Field(min_length=10, max_length=500)


class VulnerabilityModelUnavailable(RuntimeError):
    """Raised when a real DeepSeek triage result cannot be obtained."""


@dataclass(frozen=True, slots=True)
class VulnerabilityAgentResult:
    model: str | None
    status: str
    priority: str
    summary: str
    affected_assessment: str
    remediation: str
    verification: str
    evidence_gaps: list[str]
    knowledge_citations: list[dict[str, str]]


@dataclass(frozen=True, slots=True)
class VulnerabilityActionDecision:
    model: str
    action: Literal["remediate", "verify_not_affected"]
    tool_name: str
    verification_tool: str
    rationale: str
    success_criteria: str


class VulnerabilityTriageAgent:
    """Bounded specialist: RAG and LLM can advise but cannot mutate assets."""

    def __init__(
        self,
        settings: Settings,
        knowledge: KnowledgeApiService,
        *,
        tenant_id: UUID,
        principal_id: UUID,
    ) -> None:
        self._settings = settings
        self._knowledge = knowledge
        self._tenant_id = tenant_id
        self._principal_id = principal_id

    async def analyze(
        self, finding: VulnerabilityFindingRow, business_context: str | None
    ) -> VulnerabilityAgentResult:
        if not self._settings.deepseek_api_key.get_secret_value():
            raise VulnerabilityModelUnavailable("DeepSeek 未配置，无法启动漏洞研判")
        knowledge, citations = self._retrieve(finding)
        prompt = (
            "你是漏洞研判智能体。只能根据扫描器事实和本地知识依据给出公开研判，不得声称已执行修复，"
            "不得输出命令、凭据、思维链或未经证实的资产事实。严格输出一个 JSON 对象，字段仅为："
            "priority(P0/P1/P2/P3)、summary、affected_assessment、remediation、verification、evidence_gaps(字符串数组)。\n"
            f"扫描器事实：CVE={finding.cve_id}；severity={finding.severity}；cvss={finding.cvss_score}；"
            f"asset={finding.asset_name}；package={finding.package_name}；installed={finding.installed_version}；"
            f"fixed={finding.fixed_version}；scanner={finding.scanner}。\n"
            f"业务背景：{business_context or '未提供'}\n本地知识依据：{knowledge}"
        )
        try:
            async with httpx.AsyncClient() as client:
                response = await DeepSeekClient(self._settings, client).chat(
                    ChatRequest(
                        messages=(
                            ChatMessage(
                                role="system",
                                content="你是受控安全多智能体中的漏洞研判智能体，只返回合法 JSON。",
                            ),
                            ChatMessage(role="user", content=prompt),
                        ),
                        temperature=0.1,
                        max_tokens=800,
                    )
                )
            parsed = _AgentOutput.model_validate(self._json(response.content))
            return VulnerabilityAgentResult(
                model=response.model,
                status="completed",
                knowledge_citations=citations,
                **parsed.model_dump(),
            )
        except (LlmError, ValidationError, ValueError, json.JSONDecodeError) as error:
            raise VulnerabilityModelUnavailable(
                "DeepSeek 调用失败或返回格式无效，漏洞研判未完成"
            ) from error

    async def decide_next_action(
        self,
        finding: VulnerabilityFindingRow,
        *,
        triage_summary: str,
        action_tools: dict[str, str],
        verification_tools: dict[str, str],
        feedback: str | None = None,
    ) -> VulnerabilityActionDecision:
        """Use the live model to select the next action from a bounded public tool catalog."""
        if not self._settings.deepseek_api_key.get_secret_value():
            raise VulnerabilityModelUnavailable("DeepSeek 未配置，无法完成漏洞处置决策")
        action_catalog = "\n".join(
            f"- {name}: {description}" for name, description in action_tools.items()
        )
        verification_catalog = "\n".join(
            f"- {name}: {description}" for name, description in verification_tools.items()
        )
        prompt = (
            "你是漏洞处置智能体，必须执行明确的观察—决策—行动协议。\n"
            "观察：读取扫描事实、研判结论、上一步工具反馈和允许工具目录。\n"
            "决策：选择 remediate（实施补救）或 verify_not_affected（核验后排除误报）。\n"
            "行动：只能从允许目录选择 tool_name 和 verification_tool，不得虚构工具。\n"
            "严格输出一个 JSON 对象，字段仅为 action、tool_name、verification_tool、rationale、"
            "success_criteria；不得输出隐藏思维链、命令或目录外动作。\n"
            f"扫描事实：CVE={finding.cve_id}；asset={finding.asset_name}；severity={finding.severity}；"
            f"package={finding.package_name}；installed={finding.installed_version}；fixed={finding.fixed_version}；"
            f"evidence={json.dumps(finding.evidence_json, ensure_ascii=False)}。\n"
            f"研判结论：{triage_summary}\n"
            f"上一步反馈：{feedback or '无，这是首次处置决策'}\n"
            f"允许的处置工具：\n{action_catalog}\n"
            f"允许的验证工具：\n{verification_catalog}"
        )
        try:
            async with httpx.AsyncClient() as client:
                response = await DeepSeekClient(self._settings, client).chat(
                    ChatRequest(
                        messages=(
                            ChatMessage(
                                role="system",
                                content=(
                                    "你是受控漏洞处置智能体，按观察—决策—行动协议选择目录内工具，"
                                    "只返回合法 JSON。"
                                ),
                            ),
                            ChatMessage(role="user", content=prompt),
                        ),
                        temperature=0.1,
                        max_tokens=600,
                    )
                )
            parsed = _ActionOutput.model_validate(self._json(response.content))
            if (
                parsed.tool_name not in action_tools
                or parsed.verification_tool not in verification_tools
            ):
                raise ValueError("model selected a tool outside the allowed catalog")
            return VulnerabilityActionDecision(model=response.model, **parsed.model_dump())
        except (LlmError, ValidationError, ValueError, json.JSONDecodeError) as error:
            raise VulnerabilityModelUnavailable(
                "DeepSeek 调用失败、返回格式无效或选择了未授权工具，漏洞处置决策未完成"
            ) from error

    def _retrieve(self, finding: VulnerabilityFindingRow) -> tuple[str, list[dict[str, str]]]:
        try:
            bases = self._knowledge.list_knowledge_bases(tenant_id=self._tenant_id)
            if not bases:
                return "知识库为空。", []
            result = self._knowledge.retrieve(
                RetrievalRequest(
                    query=f"{finding.cve_id} {finding.package_name or ''} 漏洞影响、修复和复测要求",
                    knowledge_base_ids=[item.id for item in bases],
                    limit=3,
                ),
                tenant_id=self._tenant_id,
                principal_id=self._principal_id,
            )
            citations = [
                {"document_title": item.document_title, "excerpt": item.excerpt[:300]}
                for item in result.citations[:3]
            ]
            return (result.answer or "未检索到直接依据")[:1800], citations
        except Exception:
            return "知识库暂不可用。", []

    @staticmethod
    def _json(content: str) -> object:
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.I)
        return json.loads(cleaned)
