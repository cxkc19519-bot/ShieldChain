"""Model-directed, server-bounded ReAct collaboration over real security data."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from time import perf_counter
from uuid import UUID

import httpx
import structlog

from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError
from shieldchain.rag.api_service import KnowledgeApiService
from shieldchain.rag.schemas import RetrievalRequest

from .audit import AgentToolAuditContext, AgentToolAuditStore
from .mcp_tools import AgentToolExecutionResult, ReadOnlyAgentTool
from .response_plan_agent import OperationsResponsePlanAgent
from .schemas import AgentRoleRunView, McpToolCallView

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RoleDefinition:
    key: str
    label: str
    responsibility: str
    allowed_tools: tuple[str, ...] = ()
    fallback_tools: tuple[str, ...] = ()


_EVENTS = "security.events.list"
_ALERTS = "security.alerts.list"
_VULNERABILITIES = "security.vulnerabilities.list"
_WEAK_PASSWORDS = "security.weak_passwords.list"
_RAG = "knowledge.rag.retrieve"
AGENT_TOOL_CATALOG: dict[str, dict[str, object]] = {
    _EVENTS: {
        "label": "事件 MCP",
        "description": (
            "查询指定时间范围内由安全告警归并形成的待人工复核事件，"
            "返回事件编号、风险等级和标题。只读，不执行处置。"
        ),
        "use_when": (
            "需要了解事件总体情况、风险排序、受影响对象线索，或核对告警是否已形成调查事件时使用。"
        ),
        "do_not_use_when": (
            "只需要查看原始告警明细、查询通用安全知识，或试图执行封禁、隔离、修复时不要使用。"
        ),
        "parameters": {
            "start_at": "报告任务统一提供的查询开始时间",
            "end_at": "报告任务统一提供的查询结束时间",
            "limit": "服务端固定最多返回 50 条",
        },
        "returns": "事件编号、风险等级、事件标题、结果数量和查询摘要。",
        "limitations": "返回的是待人工复核事件线索，不代表威胁已经确认，也不包含完整原始日志。",
    },
    _ALERTS: {
        "label": "告警 MCP",
        "description": (
            "查询指定时间范围内接收的 Wazuh 安全告警，"
            "返回规则编号、严重等级和告警标题。只读，不执行处置。"
        ),
        "use_when": "需要核查告警数量、严重性、检测规则或原始检测线索时使用。",
        "do_not_use_when": (
            "需要通用知识解释、已确认漏洞清单，或试图把一条告警直接认定为成功攻击时不要使用。"
        ),
        "parameters": {
            "start_at": "报告任务统一提供的查询开始时间",
            "end_at": "报告任务统一提供的查询结束时间",
            "limit": "服务端固定最多返回 50 条",
        },
        "returns": "告警严重等级、规则编号、标题、高风险告警数量和查询摘要。",
        "limitations": (
            "告警是检测线索，可能存在误报、重复或上下文不足，必须结合事件和其他证据复核。"
        ),
    },
    _VULNERABILITIES: {
        "label": "漏洞 MCP",
        "description": (
            "从指定时间范围的告警标题和规范化证据中提取 CVE 标识及关联告警线索。"
            "只读，不进行漏洞扫描或修复。"
        ),
        "use_when": "告警或事件可能涉及公开漏洞，需要整理 CVE 线索并安排资产版本复核时使用。",
        "do_not_use_when": (
            "没有漏洞迹象、需要查询漏洞原理与修复知识，或需要确认某资产一定受影响时不要单独使用。"
        ),
        "parameters": {
            "start_at": "报告任务统一提供的查询开始时间",
            "end_at": "报告任务统一提供的查询结束时间",
            "limit": "服务端最多返回 50 个去重后的 CVE 线索",
        },
        "returns": "CVE 标识、关联告警等级与标题、结果数量和查询摘要。",
        "limitations": (
            "识别到 CVE 只表示告警中出现相关标识，不等同于资产版本已确认受影响或漏洞已被利用。"
        ),
    },
    _WEAK_PASSWORDS: {
        "label": "弱口令 MCP",
        "description": (
            "从指定时间范围的告警中筛选弱口令、密码喷洒、暴力破解等认证风险线索。"
            "只读，不读取或展示真实密码。"
        ),
        "use_when": "出现异常登录、认证失败、密码喷洒或暴力破解迹象，需要汇总身份认证风险时使用。",
        "do_not_use_when": "没有认证相关迹象、需要获取用户密码，或准备自动修改账户凭据时不要使用。",
        "parameters": {
            "start_at": "报告任务统一提供的查询开始时间",
            "end_at": "报告任务统一提供的查询结束时间",
            "limit": "服务端最多返回 50 条认证风险线索",
        },
        "returns": "关联告警等级、规则编号、标题、结果数量和查询摘要。",
        "limitations": (
            "返回的是基于告警关键词识别的认证风险线索，不证明弱密码真实存在，也不包含任何明文凭据。"
        ),
    },
    _RAG: {
        "label": "本地知识库 RAG",
        "description": (
            "使用自然语言问题检索 ShieldChain 本地知识库，"
            "返回最多 3 个相关片段形成的可引用回答。只读。"
        ),
        "use_when": (
            "需要补充法规、ATT&CK 技战术、漏洞原理、处置规范或历史调查报告中的知识依据时使用。"
        ),
        "do_not_use_when": (
            "需要查询实时事件或告警、知识库没有相关资料，"
            "或准备把检索内容当作当前事件的已确认事实时不要使用。"
        ),
        "parameters": {
            "query": "具体、完整的安全知识检索问题；仅该工具接受模型生成的 query",
            "limit": "服务端固定最多检索 3 个相关片段",
        },
        "returns": "基于本地知识库片段生成的回答；无知识库或无命中时返回明确说明。",
        "limitations": (
            "知识内容只能作为研判依据，不能证明当前资产、攻击或处置状态；检索不可用时不得扩写事实。"
        ),
    },
}
AGENT_TOOL_LABELS = {name: str(item["label"]) for name, item in AGENT_TOOL_CATALOG.items()}

_SUPERAGENT = RoleDefinition("superagent", "总控智能体", "观察公开状态并选择下一位专业智能体。")
_SPECIALISTS = {
    item.key: item
    for item in (
        RoleDefinition(
            "alert_triage",
            "告警分诊智能体",
            "对事件和告警分级、归并并指出优先项。",
            (_ALERTS, _EVENTS),
            (_ALERTS, _EVENTS),
        ),
        RoleDefinition(
            "threat_investigation",
            "威胁研判智能体",
            "关联证据与漏洞、认证线索，区分事实和待核实假设。",
            (_EVENTS, _ALERTS, _VULNERABILITIES, _WEAK_PASSWORDS),
            (_EVENTS, _ALERTS),
        ),
        RoleDefinition(
            "knowledge_retrieval",
            "知识检索智能体",
            "按需调用本地 RAG 补充可引用的安全知识。",
            (_RAG,),
            (_RAG,),
        ),
        RoleDefinition(
            "response_planning",
            "响应规划智能体",
            "依据已有结论按需补充事实，并提出需人工批准的响应建议。",
            (_EVENTS, _ALERTS, _VULNERABILITIES, _WEAK_PASSWORDS),
        ),
        RoleDefinition(
            "verification",
            "验证智能体",
            "按需复查事件或告警，并制定建议实施后的观测指标和验收条件。",
            (_EVENTS, _ALERTS),
        ),
        RoleDefinition(
            "reporting",
            "报告智能体",
            "按报告完整性需要选择数据工具，汇总事实、线索、局限性，并形成概括总结和面向人工复核的分级处置建议。",
            (_EVENTS, _ALERTS, _VULNERABILITIES, _WEAK_PASSWORDS),
            (_EVENTS, _ALERTS, _VULNERABILITIES, _WEAK_PASSWORDS),
        ),
    )
}
_FALLBACK_ORDER = tuple(_SPECIALISTS)
_REASON_CODE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class AgentToolBroker:
    """Execute allowlisted read-only tools once and cache their observations."""

    def __init__(
        self,
        tools: tuple[ReadOnlyAgentTool, ...],
        start_at: datetime,
        end_at: datetime,
        *,
        audit_store: AgentToolAuditStore | None = None,
        audit_context: AgentToolAuditContext | None = None,
    ) -> None:
        self._validate_window(start_at, end_at)
        self._tools = {tool.name: tool for tool in tools}
        self._start_at = start_at
        self._end_at = end_at
        self._cache: dict[str, McpToolCallView] = {}
        self._order: list[str] = []
        self._audit_store = audit_store
        self._audit_context = audit_context
        if (audit_store is None) != (audit_context is None):
            raise ValueError("audit store and context must be provided together")

    @property
    def results(self) -> list[McpToolCallView]:
        return [self._cache[name] for name in self._order]

    def catalog(self, allowed: tuple[str, ...]) -> list[dict[str, object]]:
        items = []
        for name in allowed:
            if name == _RAG:
                items.append({"name": name, **AGENT_TOOL_CATALOG[name]})
            elif name in self._tools:
                catalog = getattr(self._tools[name], "catalog_entry", AGENT_TOOL_CATALOG.get(name))
                if catalog is not None:
                    items.append({"name": name, **catalog})
        return items

    def available_for_role(
        self,
        role: str,
        builtins: tuple[str, ...],
        used: set[str],
    ) -> tuple[str, ...]:
        allowed = [name for name in builtins if name not in used]
        allowed.extend(
            name
            for name, tool in self._tools.items()
            if name not in used and role in getattr(tool, "allowed_roles", ())
        )
        return tuple(dict.fromkeys(allowed))

    def label(self, name: str) -> str:
        if name == _RAG:
            return AGENT_TOOL_LABELS[name]
        tool = self._tools.get(name)
        return tool.label if tool is not None else name

    async def call(self, name: str, *, role: str | None = None) -> McpToolCallView:
        if name not in self._tools:
            raise ValueError("tool is not registered")
        allowed_roles = getattr(self._tools[name], "allowed_roles", ())
        if allowed_roles and role not in allowed_roles:
            raise ValueError("tool is not allowed for this role")
        if name not in self._cache:
            tool = self._tools[name]
            arguments = {
                "start_at": self._start_at.isoformat(),
                "end_at": self._end_at.isoformat(),
                "limit": 50,
            }
            call_id = None
            started_at = perf_counter()
            if self._audit_store is not None and self._audit_context is not None:
                audit_context = (
                    replace(self._audit_context, direction="mcp_outbound")
                    if tool.provider_kind == "remote_mcp"
                    else self._audit_context
                )
                call_id = self._audit_store.start(
                    audit_context,
                    tool,
                    role=role,
                    arguments=arguments,
                    now=datetime.now(UTC),
                )
            result_bytes = None
            truncated = False
            try:
                if inspect.iscoroutinefunction(tool.call):
                    execution = await tool.call(self._start_at, self._end_at)
                else:
                    execution = await asyncio.to_thread(tool.call, self._start_at, self._end_at)
                if isinstance(execution, AgentToolExecutionResult):
                    result = execution.view
                    result_bytes = execution.result_bytes
                    truncated = execution.truncated
                else:
                    result = execution
            except asyncio.CancelledError:
                if call_id is not None and self._audit_store is not None:
                    self._audit_store.cancel(
                        call_id,
                        duration_ms=round((perf_counter() - started_at) * 1000),
                        now=datetime.now(UTC),
                    )
                raise
            except Exception as error:
                logger.warning(
                    "agent_tool_call_failed",
                    tool_name=tool.name,
                    error_type=type(error).__name__,
                )
                result = McpToolCallView(
                    name=tool.name,
                    label=tool.label,
                    status="failed",
                    reason_code="tool_dependency_failed",
                    arguments={
                        "start_at": self._start_at.isoformat(),
                        "end_at": self._end_at.isoformat(),
                        "limit": 50,
                    },
                    result_count=0,
                    summary=f"{tool.label}调用失败；未取得可信结果，需人工复核。",
                    items=[],
                )
            if call_id is not None and self._audit_store is not None:
                self._audit_store.finish(
                    call_id,
                    result,
                    duration_ms=round((perf_counter() - started_at) * 1000),
                    now=datetime.now(UTC),
                    result_bytes=result_bytes,
                    truncated=truncated,
                )
            self._cache[name] = result
            self._order.append(name)
        return self._cache[name]

    def public_facts(self, limit: int = 4500) -> str:
        if not self._order:
            return "尚未调用运营数据工具。"
        return "\n".join(f"{item.label}：{item.summary}" for item in self.results)[:limit]

    @staticmethod
    def _validate_window(start_at: datetime, end_at: datetime) -> None:
        for value in (start_at, end_at):
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("agent tool time window must use aware UTC datetimes")
        if start_at > end_at:
            raise ValueError("agent tool start_at must not be later than end_at")
        if end_at - start_at > timedelta(days=31):
            raise ValueError("agent tool time window cannot exceed 31 days")


class RealDataAgentTeam:
    """Bounded ReAct: choose a role, let it choose tools, observe, and repeat."""

    def __init__(
        self,
        settings: Settings,
        knowledge: KnowledgeApiService,
        *,
        tenant_id: UUID,
        principal_id: UUID,
        response_plan_agent: OperationsResponsePlanAgent | None = None,
    ) -> None:
        self._settings = settings
        self._knowledge = knowledge
        self._tenant_id = tenant_id
        self._principal_id = principal_id
        self._response_plan_agent = response_plan_agent

    async def run(
        self,
        tools: tuple[ReadOnlyAgentTool, ...],
        start_at: datetime,
        end_at: datetime,
        *,
        audit_store: AgentToolAuditStore | None = None,
        audit_context: AgentToolAuditContext | None = None,
        run_id: UUID | None = None,
        now: datetime | None = None,
    ) -> tuple[list[AgentRoleRunView], str | None, list[McpToolCallView]]:
        broker = AgentToolBroker(
            tools,
            start_at,
            end_at,
            audit_store=audit_store,
            audit_context=audit_context,
        )
        remaining = set(_SPECIALISTS)
        results: list[AgentRoleRunView] = []
        model: str | None = None
        selected, reason, planner_model = await self._choose(
            remaining, broker.public_facts(), results
        )
        model = planner_model
        results.append(
            AgentRoleRunView(
                role=_SUPERAGENT.key,
                label=_SUPERAGENT.label,
                status="completed" if planner_model else "fallback",
                summary=f"总控决策：{reason}",
                handoff_to=_SPECIALISTS[selected].label,
                iteration=1,
                decision_reason=reason,
            )
        )
        iteration = 2
        while remaining and iteration <= 8:
            definition = _SPECIALISTS[selected]
            response_plan = None
            if definition.key == "response_planning" and self._response_plan_agent is not None:
                if run_id is None or now is None:
                    raise ValueError("run_id and now are required for response planning")
                plan_result = await self._response_plan_agent.generate(
                    run_id=run_id,
                    public_handoffs=[
                        {"role": item.role, "summary": item.summary} for item in results
                    ],
                    observation_summaries=broker.public_facts(),
                    now=now,
                )
                summary = plan_result.reference.public_summary
                role_model = plan_result.model
                tool_reason = plan_result.decision_reason
                response_plan = plan_result.reference
                role_fallback = plan_result.used_fallback
            else:
                summary, role_model, tool_reason = await self._run_role(definition, broker, results)
                role_fallback = role_model is None
            model = model or role_model
            remaining.remove(selected)
            current = AgentRoleRunView(
                role=definition.key,
                label=definition.label,
                status="fallback" if role_fallback else "completed",
                summary=summary,
                handoff_to=None,
                iteration=iteration,
                decision_reason=tool_reason,
                response_plan=response_plan,
            )
            results.append(current)
            next_role: str | None = None
            handoff_reason = "所有专业角色均已完成。"
            if remaining:
                next_role, handoff_reason, planner_used = await self._choose(
                    remaining, broker.public_facts(), results
                )
                model = model or planner_used
            results[-1] = current.model_copy(
                update={
                    "handoff_to": _SPECIALISTS[next_role].label if next_role else None,
                    "decision_reason": f"{tool_reason}；交接决策：{handoff_reason}",
                }
            )
            if next_role is None:
                break
            selected = next_role
            iteration += 1
        return results, model, broker.results

    async def _choose(
        self, remaining: set[str], facts: str, results: list[AgentRoleRunView]
    ) -> tuple[str, str, str | None]:
        fallback = next(role for role in _FALLBACK_ORDER if role in remaining)
        fallback_reason = f"模型规划不可用，按安全降级顺序选择{_SPECIALISTS[fallback].label}。"
        if not self._settings.deepseek_api_key.get_secret_value():
            return fallback, fallback_reason, None
        prompt = json.dumps(
            {
                "remaining_roles": sorted(remaining),
                "completed": [
                    {"role": item.role, "summary": item.summary[:300]} for item in results
                ],
                "available_observation_summaries": facts,
            },
            ensure_ascii=False,
        )
        try:
            response = await self._chat(
                "你是安全多智能体的 ReAct 总控。观察公开状态后，"
                "从 remaining_roles 中选择一个下一角色。仅输出 JSON："
                '{"action":"run_role","role":"角色键","reason_code":"小写英文代码","public_reason":"不超过80字中文理由"}。'
                "不要输出思维链，不得选择列表外角色，也不得直接调用工具。",
                prompt,
                max_tokens=180,
            )
            parsed = self._json(response.content)
            role, reason_code = parsed.get("role"), parsed.get("reason_code")
            reason = " ".join(str(parsed.get("public_reason", "")).split())[:180]
            if parsed.get("action") != "run_role" or role not in remaining:
                raise ValueError("unallowed ReAct action")
            if not isinstance(reason_code, str) or not _REASON_CODE.fullmatch(reason_code):
                raise ValueError("invalid reason code")
            return (
                str(role),
                reason or f"选择{_SPECIALISTS[str(role)].label}继续分析。",
                response.model,
            )
        except (LlmError, ValueError, json.JSONDecodeError):
            return fallback, fallback_reason, None

    async def _run_role(
        self, definition: RoleDefinition, broker: AgentToolBroker, results: list[AgentRoleRunView]
    ) -> tuple[str, str | None, str]:
        if not self._settings.deepseek_api_key.get_secret_value():
            return await self._fallback_role(definition, broker)
        observations: list[str] = []
        used: set[str] = set()
        decisions: list[str] = []
        model: str | None = None
        handoffs = "\n".join(f"{item.label}：{item.summary}" for item in results[-3:])[:1800]
        for _ in range(4):
            available = broker.available_for_role(definition.key, definition.allowed_tools, used)
            prompt = json.dumps(
                {
                    "responsibility": definition.responsibility,
                    "available_tools": broker.catalog(available),
                    "previous_public_handoffs": handoffs,
                    "observations": observations,
                },
                ensure_ascii=False,
            )
            try:
                response = await self._chat(
                    f"你是{definition.label}。你要在受限 ReAct 循环中自主选择工具。"
                    "每轮只能输出一个 JSON 动作。需要数据时输出："
                    '{"action":"call_tool","tool":"工具名","query":"仅RAG可用的检索问题","public_reason":"中文理由"}；信息足够时输出：'
                    '{"action":"finish","summary":"不超过280字的中文公开结论","public_reason":"中文理由"}。'
                    "选择工具前必须阅读其 description、use_when、do_not_use_when 和 limitations；"
                    "只能选择 available_tools 中的工具；允许运行时不调用任何工具；"
                    "不得输出思维链、命令或虚构事实。",
                    prompt,
                    max_tokens=420,
                )
                model = model or response.model
                parsed = self._json(response.content)
                action = parsed.get("action")
                public_reason = " ".join(str(parsed.get("public_reason", "")).split())[:160]
                if action == "finish":
                    summary = self._plain(str(parsed.get("summary", "")))[:800]
                    if not summary:
                        raise ValueError("empty role summary")
                    decisions.append(public_reason or "现有观察已足以形成公开结论")
                    return summary, model, "工具决策：" + "；".join(decisions)
                if action != "call_tool":
                    raise ValueError("invalid role action")
                tool_name = str(parsed.get("tool", ""))
                if tool_name not in available:
                    raise ValueError("unallowed tool")
                used.add(tool_name)
                decisions.append(public_reason or f"需要调用{broker.label(tool_name)}补充证据")
                if tool_name == _RAG:
                    query = " ".join(str(parsed.get("query", "")).split())[:1000]
                    observation = await asyncio.to_thread(
                        self._retrieve, query or handoffs or definition.responsibility
                    )
                    observations.append(f"{AGENT_TOOL_LABELS[_RAG]}：{observation}")
                else:
                    observations.append(
                        self._tool_observation(await broker.call(tool_name, role=definition.key))
                    )
            except (LlmError, ValueError, json.JSONDecodeError):
                break
        summary, fallback_model = await self._summarize_observations(
            definition, observations, handoffs
        )
        reason = "；".join(decisions) if decisions else "模型动作无效，已安全结束本角色"
        return summary, model or fallback_model, "工具决策：" + reason

    async def _fallback_role(
        self, definition: RoleDefinition, broker: AgentToolBroker
    ) -> tuple[str, None, str]:
        observations: list[str] = []
        selected: list[str] = []
        for name in definition.fallback_tools:
            selected.append(AGENT_TOOL_LABELS[name])
            if name == _RAG:
                observations.append(
                    f"{AGENT_TOOL_LABELS[_RAG]}：{self._retrieve(definition.responsibility)}"
                )
            else:
                observations.append(
                    self._tool_observation(await broker.call(name, role=definition.key))
                )
        if observations:
            summary = (f"{definition.label}保守降级：" + "；".join(observations))[:800]
            reason = "模型不可用，按角色最小必需集合调用" + "、".join(selected)
        else:
            summary = (
                f"{definition.label}保守降级：未新增工具调用；保留已有公开事实并建议人工复核。"
            )
            reason = "模型不可用，本角色无强制工具，未新增调用"
        return summary, None, f"工具决策：{reason}"

    async def _summarize_observations(
        self, definition: RoleDefinition, observations: list[str], handoffs: str
    ) -> tuple[str, str | None]:
        if not observations:
            return f"{definition.label}：未选择新增工具，依据前序公开结论继续，建议人工复核。", None
        try:
            response = await self._chat(
                f"你是{definition.label}。只输出不超过280字的公开中文摘要，不输出思维链，不得编造或执行处置。",
                f"职责：{definition.responsibility}\n"
                f"工具观察：{' | '.join(observations)[:6000]}\n"
                f"前序交接：{handoffs}",
                max_tokens=360,
            )
            return self._plain(response.content)[:800], response.model
        except LlmError:
            return f"{definition.label}：模型总结不可用，已保留工具观察并建议人工复核。", None

    async def _chat(self, system: str, user: str, *, max_tokens: int):
        async with httpx.AsyncClient() as client:
            return await DeepSeekClient(self._settings, client).chat(
                ChatRequest(
                    messages=(
                        ChatMessage(role="system", content=system),
                        ChatMessage(role="user", content=user),
                    ),
                    temperature=0.0,
                    max_tokens=max_tokens,
                )
            )

    def _retrieve(self, query: str) -> str:
        try:
            bases = self._knowledge.list_knowledge_bases(tenant_id=self._tenant_id)
            if not bases:
                return "本地知识库为空。"
            response = self._knowledge.retrieve(
                RetrievalRequest(
                    query=query[:2000], knowledge_base_ids=[item.id for item in bases], limit=3
                ),
                tenant_id=self._tenant_id,
                principal_id=self._principal_id,
            )
            return response.answer[:1800] if response.answer else "未检索到可引用片段。"
        except Exception:
            return "RAG 暂不可用；不得据此扩写事实。"

    @staticmethod
    def _tool_observation(item: McpToolCallView) -> str:
        details = "；".join(item.items[:8])
        return f"{item.label}：{item.summary}" + (f"；{details}" if details else "")

    @staticmethod
    def _plain(value: str) -> str:
        return " ".join(value.replace("**", "").replace("__", "").split())

    @staticmethod
    def _json(value: str) -> dict[str, object]:
        start, end = value.find("{"), value.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("model did not return JSON")
        parsed = json.loads(value[start : end + 1])
        if not isinstance(parsed, dict):
            raise ValueError("model JSON must be an object")
        return parsed
