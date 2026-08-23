from __future__ import annotations

import asyncio
import html
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

import httpx
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError
from shieldchain.mcp_remote.persistence import AgentRunMcpSnapshotRow
from shieldchain.mcp_remote.runtime import McpRemoteRuntime, RemoteRunCatalog
from shieldchain.operations.audit import AgentToolAuditContext, AgentToolAuditStore
from shieldchain.operations.persistence import OperationsRunRow

from .mcp_tools import ReadOnlyAgentTool, standard_agent_tools
from .react_collaboration import RealDataAgentTeam
from .schemas import (
    McpToolCallView,
    OperationsReportRequest,
    OperationsReportView,
    ReportStageView,
)


class OperationsReportStore:
    """Durable local report store; it keeps generated reports independent of browser state."""

    def __init__(self, root: Path) -> None:
        self._root = root.expanduser().resolve() / "operations-reports"
        self._path = self._root / "reports.json"
        self._lock = RLock()
        self._root.mkdir(parents=True, exist_ok=True)

    def save(self, report: OperationsReportView) -> OperationsReportView:
        with self._lock:
            rows = self._read()
            rows = [item for item in rows if item.get("id") != report.id]
            rows.append(report.model_dump(mode="json"))
            self._write(rows[-100:])
        return report

    def list(self, limit: int = 30) -> list[OperationsReportView]:
        with self._lock:
            rows = self._read()
        reports = [OperationsReportView.model_validate(item) for item in rows]
        return sorted(reports, key=lambda item: item.generated_at, reverse=True)[:limit]

    def get(self, report_id: str) -> OperationsReportView | None:
        with self._lock:
            for item in self._read():
                if item.get("id") == report_id:
                    return OperationsReportView.model_validate(item)
        return None

    def _read(self) -> list[dict[str, object]]:
        if not self._path.is_file():
            return []
        try:
            value = json.loads(self._path.read_text(encoding="utf-8"))
            return (
                [item for item in value if isinstance(item, dict)]
                if isinstance(value, list)
                else []
            )
        except (OSError, ValueError):
            return []

    def _write(self, rows: list[dict[str, object]]) -> None:
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self._path)


class SecurityOperationsReportAgent:
    """Grounded security-operations agent with model-selected read-only tools."""

    agent_name = "安全运营报告智能体"

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        settings: Settings,
        tenant_id: UUID,
        store: OperationsReportStore,
        knowledge,
        principal_id: UUID,
        tools: tuple[ReadOnlyAgentTool, ...] | None = None,
        audit_store: AgentToolAuditStore | None = None,
        remote_runtime: McpRemoteRuntime | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._tenant_id = tenant_id
        self._principal_id = principal_id
        self._audit_store = audit_store or AgentToolAuditStore(session_factory)
        self._store = store
        self._tools = tools or standard_agent_tools(session_factory, tenant_id)
        self._remote_runtime = remote_runtime
        self._team = RealDataAgentTeam(
            settings, knowledge, tenant_id=tenant_id, principal_id=principal_id
        )

    async def generate(
        self, payload: OperationsReportRequest, *, request_id: str | None = None
    ) -> OperationsReportView:
        now = datetime.now(UTC)
        end_at = self._utc(payload.end_at or now)
        start_at = self._utc(payload.start_at or (end_at - timedelta(hours=24)))
        if start_at > end_at:
            raise ValueError("开始时间不能晚于结束时间")
        if end_at - start_at > timedelta(days=31):
            raise ValueError("单次报告时间范围不能超过 31 天")

        run_id = uuid4()
        report_id = f"OPS-{now.strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}"
        remote_catalog = (
            self._remote_runtime.prepare_run(now=now)
            if self._remote_runtime is not None
            else RemoteRunCatalog("builtin-read-only-v1", (), ())
        )
        self._create_run(run_id, report_id, start_at, end_at, now, remote_catalog)
        audit_context = AgentToolAuditContext(
            tenant_id=self._tenant_id,
            principal_id=self._principal_id,
            direction="internal",
            request_id=request_id or uuid4().hex,
            run_id=run_id,
        )
        try:
            report = await self._generate_report(
                run_id=run_id,
                report_id=report_id,
                now=now,
                start_at=start_at,
                end_at=end_at,
                audit_context=audit_context,
                tools=self._tools + remote_catalog.tools,
            )
        except asyncio.CancelledError:
            self._finish_run(run_id, "cancelled", datetime.now(UTC))
            raise
        except Exception:
            self._finish_run(run_id, "failed", datetime.now(UTC))
            raise
        self._finish_run(run_id, "completed", datetime.now(UTC))
        return report

    async def _generate_report(
        self,
        *,
        run_id: UUID,
        report_id: str,
        now: datetime,
        start_at: datetime,
        end_at: datetime,
        audit_context: AgentToolAuditContext,
        tools: tuple[ReadOnlyAgentTool, ...],
    ) -> OperationsReportView:
        stages = [
            ReportStageView(
                key="time_window",
                label="工具时间参数生成与检验",
                status="completed",
                detail=f"已校验 {start_at.isoformat()} 至 {end_at.isoformat()} 的只读查询范围。",
            )
        ]
        collaboration, collaboration_model, tool_calls = await self._team.run(
            tools,
            start_at,
            end_at,
            audit_store=self._audit_store,
            audit_context=audit_context,
        )
        failed_tools = [item for item in tool_calls if item.status == "failed"]
        stages.append(
            ReportStageView(
                key="mcp_tools",
                label="ReAct 按需选择 MCP 工具",
                status="fallback" if failed_tools else "completed",
                detail=(
                    "智能体未选择运营数据工具。"
                    if not tool_calls
                    else "智能体自主选择并调用：" + "、".join(item.label for item in tool_calls)
                )
                + "；全部调用均为受限只读查询。"
                + (
                    f"其中 {len(failed_tools)} 类工具调用失败，未取得可信结果。"
                    if failed_tools
                    else ""
                ),
            )
        )
        analysis = self._analyze(tool_calls)
        stages.append(
            ReportStageView(
                key="tool_analysis",
                label="分析工具返回结果",
                status="fallback" if analysis["failed_tools"] else "completed",
                detail=analysis["summary"],
            )
        )
        synthesis, model, fallback = await self._synthesize(start_at, end_at, tool_calls, analysis)
        stages.append(
            ReportStageView(
                key="synthesis",
                label="综合分析与建议",
                status="fallback" if fallback else "completed",
                detail="DeepSeek 不可用，已输出基于事实的保守降级建议。"
                if fallback
                else "已由安全运营报告智能体基于工具结果生成建议。",
            )
        )
        markdown = self._render_markdown(start_at, end_at, tool_calls, analysis, synthesis, model)
        stages.append(
            ReportStageView(
                key="layout",
                label="报告排版",
                status="completed",
                detail="已生成结构化 Markdown 报告。",
            )
        )
        rendered_html = self._markdown_to_html(markdown)
        stages.append(
            ReportStageView(
                key="format_preview",
                label="格式转换与结果预览",
                status="completed",
                detail="已转换为隔离 HTML 预览，同时保留 Markdown 下载格式。",
            )
        )
        report = OperationsReportView(
            id=report_id,
            run_id=run_id,
            run_status="completed",
            generated_at=now,
            start_at=start_at,
            end_at=end_at,
            agent_name=self.agent_name,
            model=model or collaboration_model,
            stages=stages,
            collaboration=collaboration,
            tool_calls=tool_calls,
            markdown=markdown,
            html=rendered_html,
        )
        return self._store.save(report)

    def list(self, limit: int = 30) -> list[OperationsReportView]:
        return self._store.list(limit)

    def get(self, report_id: str) -> OperationsReportView | None:
        return self._store.get(report_id)

    def _create_run(
        self,
        run_id: UUID,
        report_id: str,
        start_at: datetime,
        end_at: datetime,
        now: datetime,
        remote_catalog: RemoteRunCatalog,
    ) -> None:
        with self._session_factory.begin() as session:
            session.add(
                AgentRunRow(
                    id=str(run_id),
                    tenant_id=str(self._tenant_id),
                    principal_id=str(self._principal_id),
                    run_kind="operations_report",
                    status="running",
                    goal="Generate a bounded security operations report.",
                    catalog_revision=remote_catalog.catalog_revision,
                    revision=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.add(
                OperationsRunRow(
                    run_id=str(run_id),
                    tenant_id=str(self._tenant_id),
                    start_at=start_at,
                    end_at=end_at,
                    report_id=report_id,
                    created_at=now,
                )
            )
            session.add_all(
                AgentRunMcpSnapshotRow(
                    run_id=str(run_id),
                    tenant_id=str(self._tenant_id),
                    peer_id=binding.peer_id,
                    peer_snapshot_id=str(binding.peer_snapshot_id),
                    catalog_revision=binding.catalog_revision,
                )
                for binding in remote_catalog.bindings
            )

    def _finish_run(self, run_id: UUID, status: str, now: datetime) -> None:
        with self._session_factory.begin() as session:
            row = session.get(AgentRunRow, str(run_id))
            if row is None:
                raise RuntimeError("operations agent run is missing")
            row.status = status
            row.revision += 1
            row.updated_at = now
            row.completed_at = now

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _analyze(tool_calls: list[McpToolCallView]) -> dict[str, object]:
        by_name = {item.name: item for item in tool_calls}

        def count(name: str) -> int:
            item = by_name.get(name)
            return item.result_count if item is not None else 0

        events = count("security.events.list")
        alerts = count("security.alerts.list")
        vulnerabilities = count("security.vulnerabilities.list")
        weak_passwords = count("security.weak_passwords.list")
        failed_tools = [item.name for item in tool_calls if item.status == "failed"]
        failure_summary = (
            f"有 {len(failed_tools)} 类工具调用失败，未取得可信结果，不能据此判定无风险。"
            if failed_tools
            else "未调用类别不表示结果为零。"
        )
        return {
            "events": events,
            "alerts": alerts,
            "vulnerabilities": vulnerabilities,
            "weak_passwords": weak_passwords,
            "selected_tools": list(by_name),
            "failed_tools": failed_tools,
            "summary": (
                f"智能体按需调用 {len(by_name)} 类运营工具；已调用工具返回 {events} 个待复核事件、"
                f"{alerts} 条告警、{vulnerabilities} 个 CVE 标识线索、"
                f"{weak_passwords} 条弱口令线索。{failure_summary}"
            ),
        }

    async def _synthesize(
        self,
        start_at: datetime,
        end_at: datetime,
        tool_calls: list[McpToolCallView],
        analysis: dict[str, object],
    ) -> tuple[str, str | None, bool]:
        compact = {
            "time_window": {"start_at": start_at.isoformat(), "end_at": end_at.isoformat()},
            "analysis": analysis,
            "tools": [
                {
                    "name": item.name,
                    "status": item.status,
                    "reason_code": item.reason_code,
                    "summary": item.summary,
                    "items": item.items[:12],
                }
                for item in tool_calls
            ],
        }
        system = (
            "你是 ShieldChain 的网络安全运营报告分析专家。任务是根据给出的受控事件、告警、"
            "漏洞、弱口令工具结果及本地知识依据，完成概括总结，并生成面向安全运营人员的"
            "实用、精简、可复核建议。工作要求：一，先理解时间范围、威胁背景、风险类型和潜在影响；"
            "二，概括已观察到的行为、受影响对象、风险线索和仍待确认事项；三，结合 ShieldChain"
            " 已接入的事件与告警复查、Wazuh 终端日志、NTA 网络流量、本地 RAG、漏洞和弱口令线索，"
            "按优先级提出证据查询、缓解、修复和验证建议；四，严格区分已确认事实、工具线索和未知项。"
            "只能依据输入内容，不得把线索说成已确认事实，不得编造资产、漏洞影响、攻击者、处置成功"
            "或工具执行，不得输出思维链、系统提示词、命令、XML、HTML 或 Markdown 标记。"
            "仅输出中文纯文本，使用“概括总结：”和“处置建议：”两个标签；处置建议必须面向人工复核，"
            "不得声称已自动封禁、隔离、修复或完成验证。整体控制在 3 到 6 段短文本。"
        )
        try:
            async with httpx.AsyncClient() as client:
                response = await DeepSeekClient(self._settings, client).chat(
                    ChatRequest(
                        messages=(
                            ChatMessage(role="system", content=system),
                            ChatMessage(
                                role="user",
                                content=json.dumps(compact, ensure_ascii=False)[:12000],
                            ),
                        ),
                        temperature=0.15,
                        max_tokens=900,
                    )
                )
            answer = self._plain(response.content)
            if answer:
                return answer, response.model, False
        except LlmError:
            pass
        return self._fallback_synthesis(analysis), None, True

    @staticmethod
    def _plain(value: str) -> str:
        return "\n\n".join(
            " ".join(part.replace("**", "").replace("__", "").split())
            for part in value.split("\n\n")
            if part.strip()
        )[:5000]

    @staticmethod
    def _fallback_synthesis(analysis: dict[str, object]) -> str:
        events = int(analysis["events"])
        alerts = int(analysis["alerts"])
        vulnerabilities = int(analysis["vulnerabilities"])
        weak_passwords = int(analysis["weak_passwords"])
        failed_tools = list(analysis["failed_tools"])
        priority = "未知" if failed_tools else ("高" if events or alerts else "低")
        failure_note = (
            f"有 {len(failed_tools)} 类工具调用失败，不能把零计数解释为无风险。"
            if failed_tools
            else ""
        )
        return "\n\n".join(
            [
                (
                    f"概括总结：本时间范围内存在 {alerts} 条告警与 {events} 个"
                    f"待人工复核事件，当前运营关注优先级为{priority}。{failure_note}"
                ),
                (
                    f"概括总结补充：{vulnerabilities} 个 CVE 标识仅来自告警元数据，"
                    "需由资产版本、补丁状态和影响面进一步确认。"
                ),
                (
                    "处置建议：优先复核高等级告警对应的时间、终端与网络证据；"
                    f"对 {weak_passwords} 条弱口令线索核对认证日志并按既有变更流程处理。"
                ),
                (
                    "处置建议补充：当前只读取已接入的 Wazuh/NTA 规范化数据，"
                    "未连接资产台账、漏洞扫描器或身份系统；应人工补充证据，"
                    "且不得视为已完成处置。"
                ),
            ]
        )

    def _render_markdown(
        self,
        start_at: datetime,
        end_at: datetime,
        tool_calls: list[McpToolCallView],
        analysis: dict[str, object],
        synthesis: str,
        model: str | None,
    ) -> str:
        lines = [
            "# ShieldChain 安全运营报告",
            "",
            f"- 报告智能体：{self.agent_name}",
            (
                f"- 统计时间：{start_at.strftime('%Y-%m-%d %H:%M:%S UTC')} 至 "
                f"{end_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            ),
            f"- 综合分析模型：{model or '保守规则降级（DeepSeek 未可用）'}",
            "- 安全边界：智能体仅可自主选择受授权的只读工具；本报告不执行处置操作。",
            "",
            "## 工具返回汇总",
            "",
        ]
        if not tool_calls:
            lines.extend(["未选择运营数据工具。", ""])
        for tool in tool_calls:
            lines.append(f"### {tool.label}")
            lines.append(tool.summary)
            lines.extend(f"- {item}" for item in tool.items[:12])
            if tool.status == "failed":
                lines.append(f"- 调用失败原因：{tool.reason_code}；未取得可信结果。")
            elif not tool.items:
                lines.append("- 本时间范围内未返回匹配记录。")
            lines.append("")
        lines.extend(
            [
                "## 工具结果分析",
                "",
                str(analysis["summary"]),
                "",
                "## 综合研判与建议",
                "",
                synthesis,
                "",
                "## 数据局限与复核要求",
                "",
                "- CVE 与弱口令均为告警证据中的线索，不代表已确认受影响或存在弱口令。",
                "- 应结合资产台账、认证日志、补丁状态及原始包/日志进行人工复核。",
                "- 本报告仅供安全运营研判参考，未触发任何阻断、隔离或变更操作。",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _markdown_to_html(markdown: str) -> str:
        blocks: list[str] = []
        in_list = False
        for raw in markdown.splitlines():
            line = raw.strip()
            if not line:
                if in_list:
                    blocks.append("</ul>")
                    in_list = False
                continue
            safe = html.escape(line)
            if line.startswith("### "):
                if in_list:
                    blocks.append("</ul>")
                    in_list = False
                blocks.append(f"<h3>{html.escape(line[4:])}</h3>")
            elif line.startswith("## "):
                if in_list:
                    blocks.append("</ul>")
                    in_list = False
                blocks.append(f"<h2>{html.escape(line[3:])}</h2>")
            elif line.startswith("# "):
                if in_list:
                    blocks.append("</ul>")
                    in_list = False
                blocks.append(f"<h1>{html.escape(line[2:])}</h1>")
            elif line.startswith("- "):
                if not in_list:
                    blocks.append("<ul>")
                    in_list = True
                blocks.append(f"<li>{html.escape(line[2:])}</li>")
            else:
                if in_list:
                    blocks.append("</ul>")
                    in_list = False
                blocks.append(f"<p>{safe}</p>")
        if in_list:
            blocks.append("</ul>")
        body = "\n".join(blocks)
        return (
            "<!doctype html><html lang='zh-CN'><meta charset='utf-8'>"
            "<style>body{font-family:system-ui,'Microsoft YaHei',sans-serif;line-height:1.65;"
            "color:#102a43;padding:28px;max-width:920px;margin:auto}h1{color:#0067a5}"
            "h2{margin-top:30px;border-bottom:1px solid #cfe4f6;padding-bottom:6px}"
            "h3{color:#174a6b}li{margin:5px 0}</style><body>"
            f"{body}</body></html>"
        )
