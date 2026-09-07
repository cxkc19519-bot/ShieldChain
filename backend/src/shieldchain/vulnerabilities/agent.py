from __future__ import annotations

import json
import re
from dataclasses import dataclass
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
        knowledge, citations = self._retrieve(finding)
        fallback = VulnerabilityAgentResult(
            model=None,
            status="fallback",
            priority={"critical": "P0", "high": "P1", "medium": "P2"}.get(finding.severity, "P3"),
            summary=(
                f"{finding.cve_id} 已由 {finding.scanner} 在资产 "
                f"{finding.asset_name} 上报告，需人工核对资产版本和扫描证据。"
            ),
            affected_assessment="扫描发现是待核实证据，当前不能仅凭 CVE 标识确认资产真实受影响。",
            remediation="核对厂商公告、资产版本、业务依赖和变更窗口后，再由人工批准补丁或缓解措施。",
            verification="修复后使用同一扫描器复测，并保留版本、扫描任务和时间戳证据；通过前不得关闭。",
            evidence_gaps=["资产版本与厂商受影响范围尚需人工复核"],
            knowledge_citations=citations,
        )
        if not self._settings.deepseek_api_key.get_secret_value():
            return fallback
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
        except (LlmError, ValidationError, ValueError, json.JSONDecodeError):
            return fallback

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
