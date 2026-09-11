from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.persistence import AgentRunRow, CaseContextRow
from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError
from shieldchain.mcp_remote.persistence import AgentRunMcpSnapshotRow
from shieldchain.mcp_remote.runtime import McpRemoteRuntime, RemoteRunCatalog
from shieldchain.operations.audit import AgentToolAuditContext, AgentToolAuditStore
from shieldchain.operations.persistence import OperationsRunRow
from shieldchain.response_planning.compiler import ResponsePlanCompiler
from shieldchain.wazuh.persistence import (
    WazuhAlertRow,
    WazuhCaseEvidenceRow,
    WazuhCaseRunRow,
    WazuhReviewCaseRow,
)

from .mcp_tools import ReadOnlyAgentTool, standard_agent_tools
from .react_collaboration import RealDataAgentTeam
from .response_plan_agent import OperationsResponsePlanAgent
from .schemas import (
    AgentRoleRunView,
    ClosureLoopView,
    CrossDomainEvidenceView,
    McpToolCallView,
    OperationsReportRequest,
    OperationsReportView,
    ReasoningStepView,
    ReportStageView,
    ResponseActionAuditView,
    ResponseAuditView,
    ResponsePlanReferenceView,
    ResponseReplanAuditView,
)

_PENDING_AUTOMATION_OVERVIEW = (
    "处置计划随后进入服务端安全策略校验；实际工具调用、执行回执和状态验证结果"
    "以本报告第 10 至 12 节记录为准。"
)


class OperationsReportStore:
    """Durable local report store; it keeps generated reports independent of browser state."""

    _safe_report_id = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

    def __init__(self, root: Path) -> None:
        self._root = root.expanduser().resolve() / "operations-reports"
        self._path = self._root / "reports.json"
        self._lock = RLock()
        self._root.mkdir(parents=True, exist_ok=True)
        self._materialize_existing_reports()

    def save(self, report: OperationsReportView) -> OperationsReportView:
        with self._lock:
            rows = self._read()
            rows = [item for item in rows if item.get("id") != report.id]
            rows.append(report.model_dump(mode="json"))
            self._write(rows[-100:])
            self._write_report_files(report)
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

    def delete(self, report_id: str) -> bool:
        with self._lock:
            rows = self._read()
            match = next((item for item in rows if item.get("id") == report_id), None)
            if match is None:
                return False
            report = OperationsReportView.model_validate(match)
            for suffix in (".json", ".html", ".md"):
                self._report_path(report.id, suffix).unlink(missing_ok=True)
            self._write([item for item in rows if item.get("id") != report_id])
        return True

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
        self._write_text(self._path, json.dumps(rows, ensure_ascii=False, indent=2))

    def _report_path(self, report_id: str, suffix: str) -> Path:
        if not self._safe_report_id.fullmatch(report_id):
            raise ValueError("运营报告 ID 格式无效")
        return self._root / f"{report_id}{suffix}"

    def _write_report_files(self, report: OperationsReportView) -> None:
        self._write_text(
            self._report_path(report.id, ".json"),
            report.model_dump_json(indent=2),
        )
        self._write_text(self._report_path(report.id, ".html"), report.html)
        self._write_text(self._report_path(report.id, ".md"), report.markdown)

    def _materialize_existing_reports(self) -> None:
        with self._lock:
            for item in self._read():
                try:
                    self._write_report_files(OperationsReportView.model_validate(item))
                except (OSError, ValueError):
                    continue

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)


@dataclass(frozen=True, slots=True)
class WazuhCaseScope:
    case_id: UUID
    alert_id: UUID
    evidence_id: UUID
    source_ip: str | None
    agent_id: str | None
    agent_name: str | None
    destination_ip: str | None
    destination_port: int | None
    process_name: str | None
    parent_process_name: str | None
    rule_id: str
    severity: int
    file_id: str | None
    rule_ttl_seconds: int
    occurred_at: datetime
    title: str
    isolated_replay: bool


class ZeroTouchOutcome(Protocol):
    plan_status: str
    reason_code: str
    loop_id: UUID
    loop_status: object


class ZeroTouchResponseExecutor(Protocol):
    def execute_zero_touch_plan(
        self, *, tenant_id: UUID, plan_id: UUID, now: datetime
    ) -> ZeroTouchOutcome: ...


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
        response_plan_agent: OperationsResponsePlanAgent | None = None,
        zero_touch_executor: ZeroTouchResponseExecutor | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._tenant_id = tenant_id
        self._principal_id = principal_id
        self._audit_store = audit_store or AgentToolAuditStore(session_factory)
        self._store = store
        self._tools = tools or standard_agent_tools(session_factory, tenant_id)
        self._remote_runtime = remote_runtime
        self._response_plan_agent = response_plan_agent or OperationsResponsePlanAgent(
            settings,
            ResponsePlanCompiler(session_factory),
            session_factory,
            tenant_id=tenant_id,
        )
        self._zero_touch_executor = zero_touch_executor
        self._team = RealDataAgentTeam(
            settings,
            knowledge,
            tenant_id=tenant_id,
            principal_id=principal_id,
            response_plan_agent=self._response_plan_agent,
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
        case_scope = self._load_wazuh_case_scope(
            payload.wazuh_case_id, run_id, now, payload.rule_ttl_seconds
        )
        self._create_run(
            run_id, report_id, start_at, end_at, now, remote_catalog, case_scope=case_scope
        )
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
                case_scope=case_scope,
            )
            if (
                case_scope is not None
                and case_scope.isolated_replay
                and report.response_plan is not None
                and report.response_plan.status == "proposed"
            ):
                if self._zero_touch_executor is None:
                    raise RuntimeError("isolated replay zero-touch executor is unavailable")
                outcome = self._zero_touch_executor.execute_zero_touch_plan(
                    tenant_id=self._tenant_id,
                    plan_id=report.response_plan.plan_id,
                    now=datetime.now(UTC),
                )
                if outcome.plan_status != "completed":
                    raise RuntimeError(
                        f"isolated replay zero-touch loop stopped: {outcome.reason_code}"
                    )
                report = self._zero_touch_completed_report(report, outcome)
                self._store.save(report)
        except asyncio.CancelledError:
            self._finish_run(run_id, "cancelled", datetime.now(UTC))
            raise
        except Exception:
            self._finish_run(run_id, "failed", datetime.now(UTC))
            raise
        self._finish_run(run_id, "completed", datetime.now(UTC))
        return report

    def _zero_touch_completed_report(
        self, report: OperationsReportView, outcome: ZeroTouchOutcome
    ) -> OperationsReportView:
        reference = report.response_plan
        if reference is None:
            raise RuntimeError("zero-touch report is missing its response plan")
        completed_reference = reference.model_copy(
            update={
                "status": "completed",
                "execution_status": "verified_completed",
                "public_summary": (
                    "隔离回放响应计划已由服务端零人工策略自动接受；"
                    f"{reference.action_count} 项白名单模拟动作均执行成功并通过状态验证。"
                ),
            }
        )
        stages = [
            item.model_copy(
                update={
                    "status": "completed",
                    "detail": (
                        f"零人工演示策略已自动接受计划并完成 {reference.action_count} 项"
                        "模拟安全动作；执行后状态已由只读验证器确认。"
                    ),
                }
            )
            if item.key == "response_plan"
            else item
            for item in report.stages
        ]
        reasoning_trace = [
            item.model_copy(
                update={
                    "status": "completed",
                    "detail": (
                        "隔离回放计划已由服务端策略自动授权，并调用白名单内的模拟安全工具。"
                        if item.phase == "act"
                        else "已重新查询响应目标状态，执行结果与计划期望状态一致。"
                    ),
                    "confidence": 1.0,
                }
            )
            if item.phase in {"act", "verify"}
            else item
            for item in report.reasoning_trace
        ]
        collaboration = [
            item.model_copy(update={"response_plan": completed_reference})
            if item.role == "response_planning" and item.response_plan is not None
            else item
            for item in report.collaboration
        ]
        closure = ClosureLoopView(
            status="closed",
            observed=report.closure.observed,
            decision=report.closure.decision,
            action=(
                f"零人工演示策略自动执行了 {reference.action_count} 项白名单模拟安全动作。"
            ),
            verification="所有动作均取得执行回执，且执行后只读状态验证通过。",
            feedback="闭环已完成；执行、验证和策略记录已保存，可按运行 ID 回放。",
            human_approval_required=False,
        )
        response_audit = self._response_audit(report, outcome)
        action_lines: list[str] = []
        for action in response_audit.actions:
            def elapsed(value: int | None) -> str:
                if value is None:
                    return "未记录"
                return "<1 ms" if value == 0 else f"{value} ms"

            approval_elapsed = (
                elapsed(action.approval_duration_ms)
            )
            execution_elapsed = (
                elapsed(action.execution_duration_ms)
            )
            verification_elapsed = (
                elapsed(action.verification_duration_ms)
            )
            action_lines.extend(
                [
                    f"### {action.sequence}. {action.tool_name} v{action.tool_version}",
                    f"- 目标：{action.target_type} `{action.target}`",
                    f"- 自动授权：{action.authorization}",
                    f"- 调用 ID：{action.call_id or '未生成'}",
                    f"- 执行状态：{action.execution_status}",
                    f"- 执行回执：{'、'.join(action.attempt_outcomes) or '无公开回执'}",
                    f"- 状态验证：{action.verification_outcome or '未取得可信验证结果'}",
                    f"- 授权耗时：{approval_elapsed}",
                    f"- 执行耗时：{execution_elapsed}",
                    f"- 验证耗时：{verification_elapsed}",
                    f"- 证据引用：{'、'.join(str(item) for item in action.evidence_ids) or '无'}",
                    "",
                ]
            )
        replan_lines = [
            (
                f"- Revision {item.revision} · {item.event_type} · "
                f"{item.reason_code or '无原因码'}：{item.summary}"
            )
            for item in response_audit.replans
        ]
        actions_markdown = (
            "\n".join(action_lines) if action_lines else "- 未保存逐动作公开审计投影。"
        )
        replans_markdown = (
            "\n".join(replan_lines) if replan_lines else "- 本轮未发生失败重规划。"
        )
        audit_lines = (
            f"- 策略结果：{response_audit.policy_result}\n"
            f"- 自动执行动作：{reference.action_count} 项\n"
            "- 人工干预：0 次\n"
            f"- 计划 ID：{reference.plan_id}\n"
            f"- ReAct 循环 ID：{response_audit.loop_id or '未记录'}\n"
            f"- 循环终态：{response_audit.loop_status}（{response_audit.reason_code}）"
        )
        completed_at = max(
            (item.updated_at for item in response_audit.actions if item.updated_at),
            default=datetime.now(UTC),
        ).astimezone(timezone(timedelta(hours=8))).strftime("%H:%M:%S")

        def phase_duration(field: str) -> str:
            values = [
                value
                for item in response_audit.actions
                if (value := getattr(item, field, None)) is not None
            ]
            if not values:
                return "未记录"
            total = sum(values)
            return "<1" if total == 0 else str(total)

        approval_duration = phase_duration("approval_duration_ms")
        execution_duration = phase_duration("execution_duration_ms")
        verification_duration = phase_duration("verification_duration_ms")
        approval_pending = (
            "### 6. [时间未记录] Approve\n"
            "- classification：ACTION\n"
            "- 审批状态：pending_policy_check\n"
            "- 研判可信度：不适用\n"
            "- duration_ms：未记录"
        )
        approval_completed = (
            f"### 6. [{completed_at}] Approve\n"
            "- classification：ACTION\n"
            f"- 审批状态：automatic_approved（{response_audit.policy_result}）\n"
            "- 研判可信度：不适用\n"
            f"- duration_ms：{approval_duration}"
        )
        act_pending = (
            "### 7. [时间未记录] Act\n"
            "- classification：ACTION\n"
            "- 执行状态：not_started\n"
            "- 研判可信度：不适用\n"
            "- duration_ms：未记录"
        )
        act_completed = (
            f"### 7. [{completed_at}] Act\n"
            "- classification：ACTION\n"
            f"- 执行状态：completed；已执行 {reference.action_count} 项白名单动作\n"
            "- 研判可信度：不适用\n"
            f"- duration_ms：{execution_duration}"
        )
        verify_pending = (
            "### 8. [时间未记录] Verify\n"
            "- classification：ACTION\n"
            "- 验证状态：not_started\n"
            "- 研判可信度：不适用\n"
            "- duration_ms：未记录"
        )
        verify_completed = (
            f"### 8. [{completed_at}] Verify\n"
            "- classification：ACTION\n"
            "- 验证状态：verified_completed\n"
            "- 研判可信度：不适用\n"
            f"- duration_ms：{verification_duration}"
        )
        close_marker = "- 边界：调查记录已保存不等于安全事件已关闭。"
        close_completed = (
            close_marker
            + f"\n\n### 10. [{completed_at}] Close\n"
            "- classification：ACTION\n"
            "- 事件状态：closed\n"
            "- close_reason：response_executed_and_verified\n"
            "- 说明：响应动作已经执行，且所有必需状态验证均通过。"
        )
        markdown = (
            report.markdown
            .replace(
                _PENDING_AUTOMATION_OVERVIEW,
                "经服务端安全策略校验后，响应智能体调用白名单内的模拟安全工具"
                f"完成 {reference.action_count} 项自动化处置；所有动作均取得执行回执，"
                "处置后状态也已通过只读验证器复核。",
            )
            .replace(approval_pending, approval_completed)
            .replace(act_pending, act_completed)
            .replace(verify_pending, verify_completed)
            .replace(close_marker, close_completed)
            .replace("- 策略检查：pending", "- 策略检查：passed")
            .replace(
                "- 审批状态：pending_policy_check",
                f"- 审批状态：automatic_approved（{response_audit.policy_result}）",
            )
            .replace("- 执行状态：not_started", "- 执行状态：completed")
            .replace("- 回执状态：not_available", "- 回执状态：received_and_trusted")
            .replace(
                "- 验证状态：not_started",
                "- 验证状态：verified_completed",
            )
            .replace("- 事件状态：pending_response", "- 事件状态：closed")
            .replace(
                "- Close：仅当响应执行且验证通过，或存在明确关闭原因时发生。",
                "- Close：响应执行且验证通过；close_reason："
                "response_executed_and_verified。",
            )
            .replace(
                "\n## 附录 A：智能体协作审计轨迹",
                "\n## 附录 A：智能体协作审计轨迹"
                f"\n\n### 实际动作与回执\n\n{actions_markdown}\n\n"
                f"### 策略与重规划审计\n\n{audit_lines}\n\n{replans_markdown}\n",
            )
        )
        return report.model_copy(
            update={
                "stages": stages,
                "collaboration": collaboration,
                "response_plan": completed_reference,
                "reasoning_trace": reasoning_trace,
                "closure": closure,
                "response_audit": response_audit,
                "markdown": markdown,
                "html": self._markdown_to_html(markdown),
            }
        )

    def _response_audit(
        self, report: OperationsReportView, outcome: ZeroTouchOutcome
    ) -> ResponseAuditView:
        if report.run_id is None or report.response_plan is None:
            raise RuntimeError("zero-touch report is missing audit identifiers")
        plan = None
        trace = None
        if self._zero_touch_executor is not None:
            plan_reader = getattr(self._zero_touch_executor, "plan_by_run", None)
            trace_reader = getattr(self._zero_touch_executor, "trace", None)
            if callable(plan_reader) and callable(trace_reader):
                plan = plan_reader(tenant_id=self._tenant_id, run_id=report.run_id)
                trace = trace_reader(tenant_id=self._tenant_id, run_id=report.run_id)
        trace_by_action = {
            str(item.plan_action_id): item
            for item in (getattr(trace, "calls", None) or [])
            if item.plan_action_id is not None
        }
        revisions = getattr(plan, "revisions", None) or []
        current_revision = getattr(plan, "current_revision", None)
        current = next(
            (item for item in revisions if item.revision == current_revision),
            None,
        )
        actions: list[ResponseActionAuditView] = []
        for action in (getattr(current, "actions", None) or []):
            call = trace_by_action.get(str(action.id))
            actions.append(
                ResponseActionAuditView(
                    action_id=action.id,
                    call_id=getattr(call, "id", None),
                    sequence=action.sequence,
                    tool_name=action.tool_name,
                    tool_version=action.tool_version,
                    target_type=action.target_type,
                    target=action.target,
                    assessed_risk=action.assessed_risk,
                    authorization=(
                        getattr(call, "policy_outcome", None)
                        or "automatic_simulation_approval"
                    ),
                    execution_status=getattr(call, "status", None) or "unknown",
                    attempt_outcomes=list(getattr(call, "attempt_outcomes", None) or []),
                    verification_outcome=getattr(call, "verification_outcome", None),
                    evidence_ids=list(getattr(call, "evidence_ids", None) or action.evidence_ids),
                    updated_at=getattr(call, "updated_at", None),
                    approval_duration_ms=getattr(call, "approval_duration_ms", None),
                    execution_duration_ms=getattr(call, "execution_duration_ms", None),
                    verification_duration_ms=getattr(call, "verification_duration_ms", None),
                )
            )
        replans = [
            ResponseReplanAuditView(
                revision=item.revision,
                event_type=item.event_type,
                reason_code=item.reason_code,
                summary=item.public_summary,
                created_at=item.created_at,
            )
            for item in (getattr(plan, "events", None) or [])
            if item.reason_code is not None or "replan" in item.event_type
        ]
        loop_status = getattr(outcome.loop_status, "value", outcome.loop_status)
        return ResponseAuditView(
            mode="zero_touch_isolated_replay",
            plan_id=report.response_plan.plan_id,
            run_id=report.run_id,
            loop_id=getattr(outcome, "loop_id", None),
            policy_result="隔离回放白名单自动授权",
            loop_status=str(loop_status),
            reason_code=outcome.reason_code,
            human_interventions=0,
            actions=actions,
            replans=replans,
        )

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
        case_scope: WazuhCaseScope | None,
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
            run_id=run_id,
            now=now,
            case_id=case_scope.case_id if case_scope else None,
            target_evidence_id=case_scope.evidence_id if case_scope else None,
            target_ip=case_scope.source_ip if case_scope else None,
            target_endpoint_id=case_scope.agent_id if case_scope else None,
            target_file_id=case_scope.file_id if case_scope else None,
            rule_ttl_seconds=case_scope.rule_ttl_seconds if case_scope else 60,
            required_observation_tools=(
                (
                    "security.events.list",
                    "security.alerts.list",
                    "security.vulnerabilities.list",
                    "security.weak_passwords.list",
                    "security.network_flows.list",
                    "security.endpoint_processes.list",
                    "security.assets.list",
                    "security.indicators.list",
                )
                if case_scope is not None and case_scope.isolated_replay
                else ()
            ),
        )
        if self._settings.agent_require_live_model:
            degraded_roles = [item.label for item in collaboration if item.status != "completed"]
            missing_model_roles = [item.label for item in collaboration if not item.model]
            if degraded_roles or missing_model_roles or collaboration_model is None:
                failed = "、".join(dict.fromkeys(degraded_roles + missing_model_roles))
                raise RuntimeError(
                    "真实模型智能体执行未完成"
                    + (f"：{failed}" if failed else "：未取得模型回执")
                )
        response_plan = next(
            (
                item.response_plan
                for item in collaboration
                if item.role == "response_planning" and item.response_plan is not None
            ),
            None,
        )
        if response_plan is None:
            raise RuntimeError("response planning role did not produce a strict plan")
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
        cross_domain = self._cross_domain(tool_calls)
        reasoning_trace = self._reasoning_trace(
            collaboration=collaboration,
            tool_calls=tool_calls,
            analysis=analysis,
        )
        stages.append(
            ReportStageView(
                key="tool_analysis",
                label="分析工具返回结果",
                status="fallback" if analysis["failed_tools"] else "completed",
                detail=analysis["summary"],
            )
        )
        stages.append(
            ReportStageView(
                key="response_plan",
                label="严格响应计划编译",
                status=(
                    "fallback"
                    if response_plan.generation_status == "deterministic_fallback"
                    else "completed"
                ),
                detail=(
                    f"计划 {response_plan.plan_id} 第 {response_plan.revision} 版已保存为"
                    f" {response_plan.status}；动作数 {response_plan.action_count}，未执行。"
                )
                + (
                    f"安全降级原因：{response_plan.fallback_reason_code}。"
                    if response_plan.fallback_reason_code
                    else ""
                ),
            )
        )
        synthesis, model, fallback = await self._synthesize(start_at, end_at, tool_calls, analysis)
        if self._settings.agent_require_live_model and (fallback or model is None):
            raise RuntimeError("报告智能体未取得真实模型回执")
        closure = self._closure_loop(
            analysis=analysis,
            synthesis=synthesis,
            fallback=fallback,
            response_plan=response_plan,
        )
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
        markdown = self._render_markdown_v2(
            report_id,
            run_id,
            start_at,
            end_at,
            tool_calls,
            analysis,
            synthesis,
            model,
            response_plan,
            collaboration=collaboration,
            reasoning_trace=reasoning_trace,
            cross_domain=cross_domain,
            closure=closure,
            case_scope=case_scope,
        )
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
            response_plan=response_plan,
            reasoning_trace=reasoning_trace,
            cross_domain=cross_domain,
            closure=closure,
            markdown=markdown,
            html=rendered_html,
        )
        return self._store.save(report)

    def list(self, limit: int = 30) -> list[OperationsReportView]:
        return self._store.list(limit)

    def get(self, report_id: str) -> OperationsReportView | None:
        return self._store.get(report_id)

    def delete(self, report_id: str) -> bool:
        return self._store.delete(report_id)

    @staticmethod
    def standalone_html(report: OperationsReportView) -> str:
        return SecurityOperationsReportAgent._markdown_to_html(report.markdown)

    def _create_run(
        self,
        run_id: UUID,
        report_id: str,
        start_at: datetime,
        end_at: datetime,
        now: datetime,
        remote_catalog: RemoteRunCatalog,
        *,
        case_scope: WazuhCaseScope | None,
    ) -> None:
        with self._session_factory.begin() as session:
            session.add(
                AgentRunRow(
                    id=str(run_id),
                    tenant_id=str(self._tenant_id),
                    principal_id=str(self._principal_id),
                    run_kind="incident_investigation" if case_scope else "operations_report",
                    status="running",
                    goal=(
                        f"Investigate Wazuh case {case_scope.case_id} "
                        "and propose a bounded response."
                        if case_scope
                        else "Generate a bounded security operations report."
                    ),
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
            if case_scope is not None:
                session.add(
                    WazuhCaseRunRow(
                        run_id=str(run_id),
                        case_id=str(case_scope.case_id),
                        tenant_id=str(self._tenant_id),
                        alert_id=str(case_scope.alert_id),
                        created_at=now,
                    )
                )
                session.add(
                    CaseContextRow(
                        id=str(case_scope.case_id),
                        run_id=str(run_id),
                        tenant_id=str(self._tenant_id),
                        revision=0,
                        phase="response_planning",
                        user_goal=(
                            "分析隔离 PCAP 回放告警并形成可由零人工策略自动执行的受控响应计划。"
                            if case_scope is not None and case_scope.isolated_replay
                            else "分析真实 Wazuh 告警并形成需要人工审批的受控响应计划。"
                        ),
                        hypotheses_json=[],
                        risks_json=[],
                        plan_json=["告警分诊", "威胁研判", "知识检索", "响应规划", "验证", "报告"],
                        step_status_json={},
                        disposition_status="等待多智能体研判",
                        budget_json={
                            "step_limit": 20,
                            "steps_used": 0,
                            "loop_limit": 8,
                            "loops_used": 0,
                            "time_limit_seconds": 300,
                            "time_used_seconds": 0,
                            "token_limit": 12000,
                            "tokens_used": 0,
                            "cost_limit_usd": 2.0,
                            "cost_used_usd": 0.0,
                            "tool_call_limit": 8,
                            "tool_calls_used": 0,
                        },
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.add(self._wazuh_evidence_row(case_scope, run_id, now))
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

    def _load_wazuh_case_scope(
        self,
        case_id: UUID | None,
        run_id: UUID,
        now: datetime,
        rule_ttl_seconds: int,
    ) -> WazuhCaseScope | None:
        if case_id is None:
            return None
        with self._session_factory() as session:
            case = session.get(WazuhReviewCaseRow, str(case_id))
            if case is None or case.tenant_id != str(self._tenant_id):
                raise ValueError("Wazuh 待复核案件不存在")
            existing = session.scalar(
                select(WazuhCaseRunRow.run_id).where(
                    WazuhCaseRunRow.case_id == str(case_id),
                    WazuhCaseRunRow.tenant_id == str(self._tenant_id),
                )
            )
            if existing is not None:
                raise ValueError(f"该 Wazuh 案件已经生成调查运行：{existing}")
            alert = session.get(WazuhAlertRow, case.alert_id)
            if alert is None or alert.tenant_id != str(self._tenant_id):
                raise ValueError("Wazuh 案件缺少原始规范化告警")
            raw_file_id = alert.evidence_json.get("file_id")
            file_id = (
                raw_file_id.strip()
                if isinstance(raw_file_id, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", raw_file_id.strip())
                else None
            )
            return WazuhCaseScope(
                case_id=case_id,
                alert_id=UUID(alert.id),
                evidence_id=uuid4(),
                source_ip=alert.source_ip,
                agent_id=alert.agent_id,
                agent_name=alert.agent_name,
                destination_ip=alert.destination_ip,
                destination_port=alert.destination_port,
                process_name=(
                    str(alert.evidence_json.get("endpoint_process") or "").strip()
                    or alert.process_name
                ),
                parent_process_name=(
                    str(alert.evidence_json.get("endpoint_parent_process") or "").strip()
                    or alert.parent_process_name
                ),
                rule_id=alert.rule_id,
                severity=alert.severity,
                file_id=file_id,
                rule_ttl_seconds=rule_ttl_seconds,
                occurred_at=self._utc(alert.occurred_at),
                title=alert.title,
                isolated_replay=(
                    alert.evidence_json.get("source_kind") == "nta_pcap_isolated_replay"
                    and alert.evidence_json.get("isolated_docker_network") is True
                ),
            )

    def _wazuh_evidence_row(
        self, scope: WazuhCaseScope, run_id: UUID, now: datetime
    ) -> WazuhCaseEvidenceRow:
        payload = {
            "source_ip": scope.source_ip,
            "agent_id": scope.agent_id,
            "file_id": scope.file_id,
            "alert_id": str(scope.alert_id),
            "title": scope.title,
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return WazuhCaseEvidenceRow(
            id=str(scope.evidence_id),
            run_id=str(run_id),
            case_id=str(scope.case_id),
            tenant_id=str(self._tenant_id),
            evidence_type="wazuh_alert",
            source="wazuh",
            observed_at=scope.occurred_at,
            summary=f"Wazuh 已接收高风险告警：{scope.title}"[:512],
            raw_reference=f"wazuh:alert:{scope.alert_id}",
            integrity_sha256=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            confirmed=True,
            payload_json=payload,
            created_at=now,
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
        vulnerability_indicators = count("security.vulnerabilities.list")
        identity_indicators = count("security.weak_passwords.list")
        network_flows = count("security.network_flows.list")
        endpoint_processes = count("security.endpoint_processes.list")
        assets = count("security.assets.list")
        indicators = count("security.indicators.list")
        failed_tools = [item.name for item in tool_calls if item.status == "failed"]
        failure_summary = (
            f"有 {len(failed_tools)} 类工具调用失败，未取得可信结果，不能据此判定无风险。"
            if failed_tools
            else "未调用类别不表示结果为零。"
        )
        return {
            "events": events,
            "alerts": alerts,
            "vulnerabilities": vulnerability_indicators,
            "weak_passwords": identity_indicators,
            "selected_tools": list(by_name),
            "failed_tools": failed_tools,
            "observed_domains": [
                label
                for name, label in (
                    ("security.events.list", "事件调查"),
                    ("security.alerts.list", "终端与检测"),
                    ("security.vulnerabilities.list", "漏洞/攻击面线索"),
                    ("security.weak_passwords.list", "身份/账号关联"),
                    ("security.network_flows.list", "网络流量"),
                    ("security.endpoint_processes.list", "端点进程"),
                    ("security.assets.list", "资产上下文"),
                    ("security.indicators.list", "威胁指标"),
                    ("knowledge.rag.retrieve", "知识检索状态"),
                )
                if name in by_name and by_name[name].status != "failed"
            ],
            "summary": (
                f"智能体按需调用 {len(by_name)} 类运营工具；已调用工具返回 {events} 个待复核事件、"
                f"{alerts} 条告警、{vulnerability_indicators} 条漏洞或攻击面关联线索、"
                f"{identity_indicators} 条身份或账号关联线索、{network_flows} 条网络上下文、"
                f"{endpoint_processes} 条端点进程链、{assets} 个资产上下文和 "
                f"{indicators} 个 IOC 候选。"
                "上述线索不等同于已确认漏洞、"
                f"利用成功或弱口令。{failure_summary}"
            ),
        }

    @staticmethod
    def _cross_domain(tool_calls: list[McpToolCallView]) -> list[CrossDomainEvidenceView]:
        """Project every supported domain, including missing domains as unknown.

        A missing tool result is deliberately represented as ``not_observed`` rather
        than zero. This prevents the UI and report from turning an omitted source
        into a false negative while still making cross-domain coverage explicit.
        """

        definitions = (
            ("events", "事件调查", "security.events.list", "事件 MCP"),
            ("detections", "检测告警", "security.alerts.list", "告警 MCP"),
            ("network_traffic", "网络流量", "security.network_flows.list", "网络流量 MCP"),
            (
                "endpoint_detection",
                "端点进程",
                "security.endpoint_processes.list",
                "端点进程 MCP",
            ),
            ("assets", "资产上下文", "security.assets.list", "资产上下文 MCP"),
            (
                "threat_intelligence",
                "威胁情报与 IOC",
                "security.indicators.list",
                "威胁情报与 IOC MCP",
            ),
            ("vulnerabilities", "漏洞管理", "security.vulnerabilities.list", "漏洞 MCP"),
            ("identity", "身份认证", "security.weak_passwords.list", "身份认证 MCP"),
            ("knowledge", "知识辅助研判", "knowledge.rag.retrieve", "本地知识库"),
        )
        by_name: dict[str, list[McpToolCallView]] = {}
        for item in tool_calls:
            by_name.setdefault(item.name, []).append(item)
        result: list[CrossDomainEvidenceView] = []
        for key, label, tool_name, source in definitions:
            items = by_name.get(tool_name, [])
            observed = [item for item in items if item.status != "failed"]
            if not observed:
                result.append(
                    CrossDomainEvidenceView(
                        key=key,
                        label=label,
                        source=source,
                        result_count=0,
                        status="not_observed",
                        summary=(
                            items[-1].summary
                            if items
                            else "本次 ReAct 未选择该域；不能据此判断无风险。"
                        ),
                    )
                )
                continue
            result.append(
                CrossDomainEvidenceView(
                    key=key,
                    label=label,
                    source=source,
                    result_count=sum(item.result_count for item in observed),
                    status="observed",
                    summary="；".join(dict.fromkeys(item.summary for item in observed))[:1800],
                )
            )
        return result

    @staticmethod
    def _reasoning_trace(
        *,
        collaboration: list,
        tool_calls: list[McpToolCallView],
        analysis: dict[str, object],
    ) -> list[ReasoningStepView]:
        """Build a safe, replayable reasoning trace from public observations.

        The trace is intentionally composed from allowlisted tool summaries and
        role handoffs. It makes the investigation path reviewable without storing
        hidden prompts, chain-of-thought tokens, credentials, or raw payloads.
        """

        domain_labels = [str(value) for value in analysis.get("observed_domains", [])]
        evidence = [f"{item.label}：{item.summary}" for item in tool_calls]
        trace: list[ReasoningStepView] = [
            ReasoningStepView(
                sequence=1,
                phase="observe",
                title="观测：汇总可用安全域",
                detail=(
                    "已读取受授权只读工具的公开摘要，"
                    + (
                        f"覆盖 {len(domain_labels)} 个域：" + "、".join(domain_labels) + "。"
                        if domain_labels
                        else "当前没有可用域结果。"
                    )
                    + " 未选择的域保持未知，不会被当作零事件。"
                ),
                evidence=evidence[:8],
                domains=domain_labels,
                status=(
                    "completed"
                    if domain_labels
                    else "blocked"
                    if analysis.get("failed_tools")
                    else "pending"
                ),
                confidence=0.7 if domain_labels else 0.0,
            ),
            ReasoningStepView(
                sequence=2,
                phase="correlate",
                title="定位：建立跨域证据关联",
                detail=(
                    "总控将事件、终端检测、漏洞和身份认证线索放入同一调查上下文，"
                    "由专业角色通过交接摘要继续核对；线索之间的因果关系仍需人工复核。"
                    if len(domain_labels) >= 2
                    else "当前证据域不足以形成跨域关联，保留证据缺口并请求人工补充。"
                ),
                evidence=evidence[:8],
                domains=domain_labels,
                status="completed" if len(domain_labels) >= 2 else "pending",
                confidence=0.6 if len(domain_labels) >= 2 else 0.0,
            ),
        ]
        for item in collaboration:
            domains = list(getattr(item, "evidence_domains", ()) or domain_labels)
            trace.append(
                ReasoningStepView(
                    sequence=len(trace) + 1,
                    phase="collaborate",
                    title=f"协同：第 {item.iteration} 轮 · {item.label}",
                    detail=item.summary,
                    evidence=[item.decision_reason] if item.decision_reason else [],
                    domains=domains,
                    status="completed" if item.status == "completed" else "blocked",
                    confidence=0.6 if item.status == "completed" else 0.0,
                )
            )
        trace.extend(
            [
                ReasoningStepView(
                    sequence=len(trace) + 1,
                    phase="decide",
                    title="定性与决策：形成可复核建议",
                    detail="已综合公开证据、角色交接和数据局限，输出区分事实、线索与未知项的研判建议。",
                    evidence=[str(analysis.get("summary", ""))],
                    domains=domain_labels,
                    status="completed",
                    confidence=0.6 if tool_calls else 0.0,
                ),
                ReasoningStepView(
                    sequence=len(trace) + 2,
                    phase="act",
                    title="动作：进入受控处置边界",
                    detail="仅生成需要人工批准的响应建议；本次报告未执行封禁、隔离、账号或修复动作。",
                    evidence=[],
                    domains=["处置控制"],
                    status="pending",
                    confidence=0.0,
                ),
                ReasoningStepView(
                    sequence=len(trace) + 3,
                    phase="verify",
                    title="验证：定义回执与新遥测条件",
                    detail="待人工批准并执行受控动作后，重新查询相关域的告警、事件和身份/漏洞状态；验证失败则回到总控重新规划。",
                    evidence=[],
                    domains=domain_labels,
                    status="pending",
                    confidence=0.0,
                ),
                ReasoningStepView(
                    sequence=len(trace) + 4,
                    phase="close",
                    title="闭环：保存可回放调查记录",
                    detail="报告、工具摘要、角色交接和验证条件已持久化，可供人工复核与后续重规划使用。",
                    evidence=[],
                    domains=["审计"],
                    status="completed",
                    confidence=1.0,
                ),
            ]
        )
        return trace

    @staticmethod
    def _closure_loop(
        *,
        analysis: dict[str, object],
        synthesis: str,
        fallback: bool,
        response_plan: ResponsePlanReferenceView,
    ) -> ClosureLoopView:
        observed = str(analysis.get("summary", "已完成受控数据观测。"))
        decision = synthesis.split("\n\n", 1)[0][:600] or "等待人工复核。"
        feedback = (
            "当前为保守降级结果；若人工补充新证据或验证失败，应把新遥测反馈给总控重新规划。"
            if fallback
            else "若验证条件不满足，应把新遥测与失败原因反馈给总控重新规划，"
            "而不是将动作标记为成功。"
        )
        return ClosureLoopView(
            status="analysis_complete",
            observed=observed,
            decision=decision,
            action=(
                f"已生成 {response_plan.action_count} 项响应计划动作；"
                "尚未进入接受或审批流程，本次未执行任何处置。"
            ),
            verification="批准后需读取动作回执和新遥测，核对预先定义的成功/失败条件。",
            feedback=feedback,
            human_approval_required=True,
        )

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

    def _render_markdown_v2(
        self,
        report_id: str,
        run_id: UUID,
        start_at: datetime,
        end_at: datetime,
        tool_calls: list[McpToolCallView],
        analysis: dict[str, object],
        synthesis: str,
        model: str | None,
        response_plan: ResponsePlanReferenceView,
        *,
        collaboration: list[AgentRoleRunView],
        reasoning_trace: list[ReasoningStepView],
        cross_domain: list[CrossDomainEvidenceView],
        closure: ClosureLoopView,
        case_scope: WazuhCaseScope | None,
    ) -> str:
        """Render the human report separately from detailed agent/tool audit records."""

        del synthesis, reasoning_trace, closure
        failed_tools = list(analysis["failed_tools"])
        alerts = int(analysis["alerts"])
        events = int(analysis["events"])
        risk_level = "未知" if failed_tools else "高" if alerts or events else "低"
        event_overview = self._event_overview(
            start_at=start_at,
            end_at=end_at,
            case_scope=case_scope,
            cross_domain=cross_domain,
            response_plan=response_plan,
            risk_level=risk_level,
        )
        china_tz = timezone(timedelta(hours=8))
        recorded_at = datetime.now(UTC).astimezone(china_tz)
        detected_at = case_scope.occurred_at.astimezone(china_tz) if case_scope else None
        detected_time = detected_at.strftime("%H:%M:%S") if detected_at else "时间未记录"
        role_runs = {item.role: item for item in collaboration}

        def role_time(role: str) -> str:
            started_at = getattr(role_runs.get(role), "started_at", None)
            return (
                started_at.astimezone(china_tz).strftime("%H:%M:%S")
                if started_at is not None
                else "时间未记录"
            )

        def role_duration(role: str) -> str:
            duration_ms = getattr(role_runs.get(role), "duration_ms", None)
            return str(duration_ms) if duration_ms is not None else "未记录"
        event_binding = str(case_scope.case_id) if case_scope else f"RUN-{run_id}"
        evidence_id = str(case_scope.evidence_id) if case_scope else f"RUN-{run_id}"
        target = case_scope.destination_ip if case_scope else None
        target_with_port = (
            f"{target}:{case_scope.destination_port}"
            if target and case_scope and case_scope.destination_port
            else target or "未记录"
        )
        process_chain = "未记录"
        if case_scope and case_scope.process_name:
            process_chain = (
                f"{case_scope.parent_process_name} → {case_scope.process_name}"
                if case_scope.parent_process_name
                else case_scope.process_name
            )
        event_type = (
            "高风险漏洞利用探测 / 疑似漏洞利用尝试"
            if case_scope
            else "指定时间范围安全运营研判"
        )
        actions = []
        if case_scope and case_scope.agent_id:
            actions.append("隔离受控演示端点")
        if case_scope and case_scope.file_id:
            actions.append("隔离受控演示文件")
        if case_scope and case_scope.source_ip:
            actions.append("临时阻断受控演示源地址")
        if not actions:
            actions.append("继续收集证据并依据策略决定后续动作")

        lines = [
            "# 基于智能体的自动化安全运营闭环报告",
            "",
            f"- 报告 ID：{report_id}",
            f"- 调查运行 ID：{run_id}",
            "",
            "## 1. 事件摘要",
            "",
            *event_overview,
            "",
            "## 2. 当前结论",
            "",
            f"- 当前风险等级：{risk_level}",
            f"- 当前定性：{event_type}",
            "- 是否确认入侵：否；检测签名命中不等于漏洞存在或利用成功。",
            "- 证据状态：已确认存在攻击尝试相关检测信号；跨域关联属于分析推断。",
            "- 当前事件状态：pending_response；执行并验证通过前不得关闭。",
            "",
            "## 3. 攻击活动时间线",
            "",
            "本时间线只描述攻击者或异常行为，不包含智能体工作过程和防守动作。",
            "",
        ]
        if case_scope:
            lines.extend(
                [
                    f"### 1. [{detected_time}] Detect",
                    "- classification：FACT",
                    "- verification_status：verified",
                    f"- 事实：规则 `{case_scope.rule_id}` 命中。",
                    f"- 网络：`{case_scope.source_ip or '未记录'}` → `{target_with_port}`。",
                    f"- evidence_id：`{evidence_id}`",
                    f"- event_binding：`{event_binding}`",
                    "- duration_ms：不适用（检测事件时间点）",
                    "",
                    f"### 2. [{detected_time}] Observe",
                    "- classification：FACT",
                    "- verification_status：observed",
                    f"- 事实：端点上下文记录到 `{process_chain}` 进程关联。",
                    "- 边界：进程关联不能证明恶意代码执行成功。",
                    f"- evidence_id：`{evidence_id}`",
                    "- duration_ms：不适用（观测事件时间点）",
                    "",
                    "### 3. [时间未记录] Attack Outcome",
                    "- classification：UNKNOWN",
                    "- verification_status：not_verified",
                    "- 未确认：漏洞利用成功、任意代码执行、生产环境受影响及横向移动。",
                ]
            )
        else:
            lines.extend(
                [
                    "### 1. [时间未记录] Detect / Observe",
                    "- classification：FACT",
                    f"- 事实：工具返回 {alerts} 条告警和 {events} 个事件。",
                    "- 边界：未调用数据域保持 UNKNOWN。",
                ]
            )

        lines.extend(
            [
                "",
                "## 4. 安全运营调查时间线",
                "",
                f"### 1. [{detected_time}] Detect",
                "- actor：探针 / XDR / Wazuh",
                "- classification：FACT",
                "- 状态：completed",
                "- 说明：检测信号进入安全运营流程。",
                "- duration_ms：不适用（检测事件时间点）",
                "",
                f"### 2. [{role_time('superagent')}] Correlate",
                "- actor：总控智能体",
                "- classification：INFERENCE",
                "- 状态：completed",
                "- 说明：将网络检测、端点上下文和已调用安全域绑定到同一调查。",
                "- 边界：关联推断不会提升原始证据等级。",
                f"- duration_ms：{role_duration('superagent')}",
                "",
                f"### 3. [{role_time('threat_investigation')}] Investigate",
                "- actor：威胁研判智能体",
                "- classification：INFERENCE",
                f"- 状态：completed；研判可信度：{'60%' if case_scope else '未量化'}",
                f"- 说明：研判为“{event_type}”；这不是利用成功事实。",
                f"- duration_ms：{role_duration('threat_investigation')}",
                "",
                f"### 4. [{role_time('alert_triage')}] Assess",
                "- actor：告警分诊智能体",
                "- classification：INFERENCE",
                f"- 状态：completed；优先级：{risk_level}",
                "- 未解决：应用版本、利用结果、生产关联及后续攻击行为。",
                f"- duration_ms：{role_duration('alert_triage')}",
                "",
                f"### 5. [{role_time('response_planning')}] Decide",
                "- actor：响应规划智能体",
                "- classification：ACTION",
                f"- 状态：completed；计划：`{response_plan.plan_id}` "
                f"Revision {response_plan.revision}",
                f"- 说明：生成 {response_plan.action_count} 项建议动作；建议不等于执行。",
                f"- duration_ms：{role_duration('response_planning')}",
                "",
                "### 6. [时间未记录] Approve",
                "- classification：ACTION",
                "- 审批状态：pending_policy_check",
                "- 研判可信度：不适用",
                "- duration_ms：未记录",
                "",
                "### 7. [时间未记录] Act",
                "- classification：ACTION",
                "- 执行状态：not_started",
                "- 研判可信度：不适用",
                "- duration_ms：未记录",
                "",
                "### 8. [时间未记录] Verify",
                "- classification：ACTION",
                "- 验证状态：not_started",
                "- 研判可信度：不适用",
                "- duration_ms：未记录",
                "",
                f"### 9. [{recorded_at.strftime('%H:%M:%S')}] Archive",
                "- classification：ACTION",
                "- 调查记录状态：archived",
                "- 事件状态：pending_response",
                "- 说明：调查轮次、工具调用、交接、计划和验证条件已持久化。",
                "- 边界：调查记录已保存不等于安全事件已关闭。",
                "",
                "## 5. 已确认事实",
                "",
            ]
        )
        if case_scope:
            lines.extend(
                [
                    f"- FACT｜规则 `{case_scope.rule_id}` 已命中｜confidence：100%｜"
                    f"verification_status：verified｜evidence_id：`{evidence_id}`",
                    f"- FACT｜源 `{case_scope.source_ip or '未记录'}`，目标 `{target_with_port}`｜"
                    f"confidence：100%｜verification_status：observed｜evidence_id：`{evidence_id}`",
                    f"- FACT｜端点进程上下文 `{process_chain}` 已记录｜confidence：100%｜"
                    f"verification_status：observed｜evidence_id：`{evidence_id}`",
                ]
            )
            if case_scope.isolated_replay:
                lines.append(
                    "- FACT｜本事件来自隔离 PCAP 演示回放并限定在受控演示目标｜"
                    "confidence：100%｜verification_status：verified｜不涉及生产目标。"
                )
        else:
            lines.append("- FACT｜工具返回的告警与事件计数已记录；未调用域保持 UNKNOWN。")

        lines.extend(["", "## 6. 跨域证据关联", ""])
        for item in cross_domain:
            if item.key == "knowledge":
                classification, verification = "REFERENCE", "context_only"
                summary = "仅记录检索状态；知识库具体内容未进入报告或主证据链。"
            elif item.key in {
                "events",
                "detections",
                "network_traffic",
                "endpoint_detection",
            }:
                classification = "FACT" if item.status == "observed" else "UNKNOWN"
                verification = "observed" if item.status == "observed" else "not_observed"
                summary = item.summary
            else:
                classification = "CORRELATED" if item.status == "observed" else "UNKNOWN"
                verification = "correlated" if item.status == "observed" else "not_observed"
                summary = (
                    "返回漏洞或攻击面关联线索；未确认资产存在漏洞或利用成功。"
                    if item.key == "vulnerabilities" and item.status == "observed"
                    else "返回身份或账号关联线索；当前无证据证明存在弱口令。"
                    if item.key == "identity" and item.status == "observed"
                    else item.summary
                )
            count = item.result_count if item.status == "observed" else "UNKNOWN"
            lines.append(
                f"- {classification}｜{item.label}｜状态：{item.status}｜结果数：{count}｜"
                f"verification_status：{verification}｜{summary}"
            )

        lines.extend(["", "## 7. 智能体研判结果", ""])
        increments = {
            "superagent": "确定调查顺序与角色交接，不新增事件事实。",
            "threat_investigation": "形成疑似攻击尝试研判；利用是否成功仍为 UNKNOWN。",
            "knowledge_retrieval": "完成背景检索；可靠性不足，未提升当前结论。",
            "alert_triage": f"将调查优先级维持为{risk_level}，未改变事实等级。",
            "verification": "定义处置后验证条件；未把待验证状态描述为成功。",
            "reporting": "整理事实、推断和未知项，不新增遥测事实。",
            "response_planning": f"生成 {response_plan.action_count} 项建议动作，等待策略校验。",
        }
        for item in collaboration:
            started_text = (
                item.started_at.astimezone(china_tz).isoformat()
                if item.started_at
                else "未记录"
            )
            finished_text = (
                item.finished_at.astimezone(china_tz).isoformat()
                if item.finished_at
                else "未记录"
            )
            duration_text = item.duration_ms if item.duration_ms is not None else "未记录"
            lines.extend(
                [
                    f"### {item.iteration}. {item.label}",
                    f"- 输入摘要：{'、'.join(item.evidence_domains) or '前序公开状态'}。",
                    f"- 新增发现：{increments.get(item.role, '完成本角色职责，未新增独立事实。')}",
                    "- 判断结果：Agent 推断不作为 FACT。",
                    "- 未解决问题：应用版本、利用结果、生产影响及后续攻击活动。",
                    f"- 交接目标：{item.handoff_to or '无；本轮协作结束'}",
                    f"- 输出状态：{'completed' if item.status == 'completed' else 'fallback'}；"
                    f"模型回执：{item.model or '未取得'}",
                    f"- 开始时间：{started_text}",
                    f"- 完成时间：{finished_text}",
                    f"- duration_ms：{duration_text}",
                    "",
                ]
            )

        unknowns = [
            "目标应用具体版本尚未确认｜原因：告警与回放证据未携带资产版本指纹。",
            "当前证据不能确认漏洞利用是否成功｜原因：检测信号证明请求命中规则，未提供目标成功响应或利用结果。",
            "当前证据不能确认是否成功执行任意代码｜原因：进程关联是上下文映射，未提供命令输出、退出码或新进程执行回执。",
            "当前没有足够证据确认发生横向移动｜原因：未观测到跨主机认证、远程执行或后续横向流量。",
        ]
        if case_scope is None or not case_scope.isolated_replay:
            unknowns.append(
                "当前证据不能确认是否影响生产环境｜原因：缺少资产环境标签和生产资产绑定证据。"
            )
        if any(item.key == "identity" and item.status == "observed" for item in cross_domain):
            unknowns.append(
                "身份或账号关联线索不能证明存在弱口令｜原因：账号关联不是认证成功事件，且未取得密码审计或认证日志。"
            )
        lines.extend(["## 8. 未确认事项", ""])
        lines.extend(f"- UNKNOWN｜{item}" for item in unknowns)
        lines.extend(
            [
                "",
                "## 9. 响应建议",
                "",
                f"- ACTION｜计划 ID：`{response_plan.plan_id}`｜Revision {response_plan.revision}",
                f"- ACTION｜建议动作数：{response_plan.action_count}；建议不等于执行。",
                *(f"- ACTION｜{item}。" for item in actions),
                "- ACTION｜核查应用版本、生产环境关联性及后续异常行为。",
                "",
                "## 10. 审批与执行状态",
                "",
                "- 策略检查：pending",
                "- 审批状态：pending_policy_check",
                "- 执行状态：not_started",
                "- 回执状态：not_available",
                "- 回滚支持：是",
                "- 授权边界：仅允许证据绑定、目标白名单与注册工具全部通过的动作。",
                "",
                "## 11. 验证条件",
                "",
                "- 验证状态：not_started",
                "- 成功条件：每项动作取得可信回执，且只读验证器返回期望状态。",
                "- 失败条件：动作失败、回执缺失、状态不一致或出现新的高风险遥测。",
                "- 失败处理：把原因与新遥测反馈给总控智能体重新规划。",
                "",
                "## 12. 当前事件状态",
                "",
                "- 事件状态：pending_response",
                "- 调查记录状态：archived",
                "- Archive：当前调查轮次已保存，可在获得新证据后再次调查。",
                "- Close：仅当响应执行且验证通过，或存在明确关闭原因时发生。",
                "",
                "## 附录 A：智能体协作审计轨迹",
                "",
                f"- 报告 ID：`{report_id}`",
                f"- 运行 ID：`{run_id}`",
                f"- 模型：{model or '未取得模型回执'}",
                f"- 角色数：{len(collaboration)}",
                "- 说明：主报告只展示增量结论，结构化报告保留公开角色状态。",
                "",
                "## 附录 B：工具调用记录",
                "",
            ]
        )
        for index, item in enumerate(tool_calls, start=1):
            if item.name == "knowledge.rag.retrieve":
                continue
            classification = (
                "FACT"
                if item.name in {"security.events.list", "security.alerts.list"}
                else "CORRELATED"
            )
            lines.append(
                f"- TOOL-{index:03d}｜{item.label}｜{classification}｜状态：{item.status}｜"
                f"结果数：{item.result_count}｜{item.summary}"
            )
        knowledge_calls = [item for item in tool_calls if item.name == "knowledge.rag.retrieve"]
        lines.extend(
            [
                "",
                "## 附录 C：知识库检索记录",
                "",
                f"- 调用次数：{len(knowledge_calls)}",
                "- classification：REFERENCE",
                "- verification_status：context_only",
                "- 主证据链：未纳入",
                "- 具体知识内容：不在报告中展示。",
                "- 结论：未获得足够可靠的受影响版本或 CVE 信息；不得提升事实等级。",
            ]
        )
        return "\n".join(lines)

    def _render_markdown(
        self,
        report_id: str,
        run_id: UUID,
        start_at: datetime,
        end_at: datetime,
        tool_calls: list[McpToolCallView],
        analysis: dict[str, object],
        synthesis: str,
        model: str | None,
        response_plan: ResponsePlanReferenceView,
        *,
        collaboration: list[AgentRoleRunView],
        reasoning_trace: list[ReasoningStepView],
        cross_domain: list[CrossDomainEvidenceView],
        closure: ClosureLoopView,
        case_scope: WazuhCaseScope | None,
    ) -> str:
        alerts = int(analysis["alerts"])
        events = int(analysis["events"])
        failed_tools = list(analysis["failed_tools"])
        observed_domains = [item for item in cross_domain if item.status == "observed"]
        risk_level = "未知" if failed_tools else "高" if alerts or events else "低"
        event_overview = self._event_overview(
            start_at=start_at,
            end_at=end_at,
            case_scope=case_scope,
            cross_domain=cross_domain,
            response_plan=response_plan,
            risk_level=risk_level,
        )
        lines = [
            "# 基于智能体的自动化安全运营闭环报告",
            "",
            f"- 报告 ID：{report_id}",
            f"- 调查运行 ID：{run_id}",
            (
                f"- 调查时间范围：{start_at.strftime('%Y-%m-%d %H:%M:%S UTC')} 至 "
                f"{end_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            ),
            "",
            "## 1. 事件概述",
            "",
            *event_overview,
            "",
            "## 2. 多源异常证据",
            "",
        ]
        for item in cross_domain:
            state = "已观测" if item.status == "observed" else "未观测"
            lines.append(
                f"- {item.label}｜来源：{item.source}｜状态：{state}｜"
                f"结果数：{item.result_count}｜{item.summary}"
            )
        lines.append("")
        if not tool_calls:
            lines.extend(["本次没有取得工具返回；未观测不能解释为没有风险。", ""])
        grouped_tools: dict[str, list[McpToolCallView]] = {}
        for tool in tool_calls:
            grouped_tools.setdefault(tool.name, []).append(tool)
        for calls in grouped_tools.values():
            tool = calls[0]
            successful = [item for item in calls if item.status != "failed"]
            failed = [item for item in calls if item.status == "failed"]
            summaries = list(
                dict.fromkeys(" ".join(item.summary.split())[:600] for item in calls)
            )
            evidence = list(
                dict.fromkeys(
                    " ".join(value.split())[:500]
                    for item in successful
                    for value in item.items
                )
            )
            lines.extend(
                [
                    f"### {tool.label}",
                    f"- 调用次数：{len(calls)}；成功：{len(successful)}；失败：{len(failed)}。",
                    f"- 去重结果数：{len(evidence)}。",
                ]
            )
            lines.extend(f"- 摘要：{value}" for value in summaries[:3])
            lines.extend(f"- 证据：{value}" for value in evidence[:8])
            for failed_call in failed:
                lines.append(
                    f"- 调用失败原因：{failed_call.reason_code}；未取得可信结果。"
                )
            if not evidence and not failed:
                lines.append("- 本时间范围内未返回匹配记录；这不代表该域不存在风险。")
            lines.append("")

        lines.extend(
            [
                "## 3. 攻击调查时间线",
                "",
                "时间线仅记录公开观测、证据关联、角色交接、动作和验证状态。",
                "",
            ]
        )
        for step in reasoning_trace:
            domains = "、".join(step.domains) if step.domains else "未标注域"
            step_status = {
                "completed": "已完成",
                "pending": "待执行",
                "blocked": "未完成",
            }[step.status]
            lines.extend(
                [
                    f"### {step.sequence}. {step.title}",
                    (
                        f"- 阶段：{step.phase}；状态：{step_status}；"
                        f"可信度：{step.confidence:.0%}；证据域：{domains}"
                    ),
                    f"- 公开说明：{step.detail}",
                ]
            )
            lines.extend(f"- 依据：{item}" for item in step.evidence[:8])
            lines.append("")

        lines.extend(
            [
                "## 4. 智能体可审计判断依据",
                "",
                "仅展示角色输出、证据引用和公开决策理由。",
                "",
            ]
        )
        for item in collaboration:
            role_status = "已完成" if item.status == "completed" else "未取得真实模型结果"
            domains = "、".join(item.evidence_domains) or "未记录"
            lines.extend(
                [
                    f"### {item.iteration}. {item.label}",
                    f"- 执行状态：{role_status}",
                    f"- 模型回执：{item.model or '无'}",
                    f"- 证据域：{domains}",
                    f"- 角色输出：{item.summary}",
                    f"- 公开决策理由：{item.decision_reason or '未记录'}",
                    f"- 交接对象：{item.handoff_to or '闭环结束'}",
                    "",
                ]
            )

        role_states = "；".join(
            f"{item.label}={'完成' if item.status == 'completed' and item.model else '未完成'}"
            for item in collaboration
        )
        observed_labels = "、".join(item.label for item in observed_domains) or "无"
        missing_labels = (
            "、".join(item.label for item in cross_domain if item.status == "not_observed")
            or "无"
        )
        lines.extend(
            [
                "## 5. 风险评估与处置计划",
                "",
                f"- 风险级别：{risk_level}",
                f"- 综合研判：{synthesis}",
                f"- 计划 ID：{response_plan.plan_id}",
                f"- 计划版本：Revision {response_plan.revision}",
                f"- 计划状态：{response_plan.status}",
                f"- 候选动作数：{response_plan.action_count}",
                f"- 计划摘要：{response_plan.public_summary}",
                "",
                "## 6. 零人工策略授权结果",
                "",
                "- 策略授权结果：尚未进入策略授权阶段。",
                "- 授权边界：只有满足隔离回放白名单、证据绑定、目标约束"
                "和工具策略的动作才可自动执行。",
                "- 人工干预：0 次；若策略拒绝，动作保持未执行并记录原因。",
                "",
                "## 7. 安全工具调用与执行回执",
                "",
                "- 执行事实：尚未取得受信工具执行回执，不能宣称动作成功。",
                "",
                "## 8. 处置前后状态对比",
                "",
                f"- 处置前：{closure.observed}",
                "- 已规划动作：尚未执行。",
                "- 处置后：尚未取得执行后遥测，无法进行状态对比。",
                "",
                "## 9. 验证结果与失败重规划",
                "",
                f"- 验证状态：{closure.verification}",
                f"- 反馈与重规划：{closure.feedback}",
                "- 可信结论：没有执行回执和执行后遥测时，不将计划标记为成功。",
                "",
                "## 10. 智能体真实执行审计",
                "",
                f"- 报告 ID：{report_id}",
                f"- 运行 ID：{run_id}",
                f"- 模型：{model or '未取得模型回执'}",
                f"- 智能体角色数：{len(collaboration)}",
                f"- 工具调用数：{len(tool_calls)}",
                f"- 角色状态：{role_states or '未记录'}",
                "",
                "## 11. 影响范围与事件结论",
                "",
                f"- 已确认覆盖域：{observed_labels}。",
                f"- 未观测域：{missing_labels}；未观测不能解释为未受影响。",
                f"- 当前结论：{closure.decision}",
                "- 数据边界：CVE、弱口令、知识库内容和告警标题均只能作为线索；"
                "只有当前事件的受信遥测与工具回执可证明处置状态。",
                "",
                "## 12. 后续优化建议",
                "",
                "- 对未观测安全域补充对应遥测接入，并保留来源、时间与完整性校验。",
                "- 持续核验处置目标状态；验证失败时将新遥测和原因码反馈给总控重新规划。",
                "- 定期复核白名单工具、授权策略和回滚能力，确保自动化处置保持最小权限。",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _event_overview(
        *,
        start_at: datetime,
        end_at: datetime,
        case_scope: WazuhCaseScope | None,
        cross_domain: list[CrossDomainEvidenceView],
        response_plan: ResponsePlanReferenceView,
        risk_level: str,
    ) -> list[str]:
        china_tz = timezone(timedelta(hours=8))
        observed = "、".join(
            item.label for item in cross_domain if item.status == "observed"
        ) or "已接入安全数据"
        if case_scope is None:
            start_text = start_at.astimezone(china_tz).strftime("%Y年%m月%d日%H时%M分")
            end_text = end_at.astimezone(china_tz).strftime("%Y年%m月%d日%H时%M分")
            return [
                f"{start_text}至{end_text}，安全运营智能体对指定时间范围内的"
                f"{observed}进行了自动汇聚与关联分析。",
                f"经综合研判，本时间范围的风险关注级别为{risk_level}；响应规划智能体"
                f"生成了 {response_plan.action_count} 项受控处置建议，具体证据和数据边界"
                "见后续章节。",
                _PENDING_AUTOMATION_OVERVIEW,
            ]

        occurred = case_scope.occurred_at.astimezone(china_tz).strftime(
            "%Y年%m月%d日%H时%M分%S秒"
        )
        target = case_scope.destination_ip or case_scope.agent_name or case_scope.agent_id
        target_text = f"服务器 `{target}`" if target else "目标服务器"
        if case_scope.destination_port:
            target_text += f" 的 `{case_scope.destination_port}` 端口"
        network = (
            f"网络安全探针同时记录到外部地址 `{case_scope.source_ip}` 向{target_text}发起异常通信。"
            if case_scope.source_ip
            else f"网络安全探针同时记录到{target_text}存在异常通信。"
        )
        process = ""
        if case_scope.process_name:
            chain = (
                f"`{case_scope.parent_process_name}` → `{case_scope.process_name}`"
                if case_scope.parent_process_name
                else f"`{case_scope.process_name}`"
            )
            endpoint = case_scope.agent_name or case_scope.agent_id or "目标端点"
            process = f"端点 `{endpoint}` 的进程上下文显示 {chain} 调用链。"
        action_candidates = []
        if case_scope.agent_id:
            action_candidates.append("端点隔离")
        if case_scope.file_id:
            action_candidates.append("恶意文件隔离")
        if case_scope.source_ip:
            action_candidates.append("恶意连接阻断")
        action_text = "、".join(action_candidates) or "受控响应"
        return [
            f"{occurred}，XDR/Wazuh 平台检测到{target_text}出现高风险安全告警："
            f"“{case_scope.title}”（规则 `{case_scope.rule_id}`，等级 {case_scope.severity}）。"
            f"{network}{process}",
            f"安全运营智能体自动接收相关告警，并对{observed}进行关联分析。经综合研判后，"
            f"智能体将本事件列为{risk_level}风险，并生成 {response_plan.action_count} 项处置策略，"
            f"候选范围包括{action_text}。",
            _PENDING_AUTOMATION_OVERVIEW,
        ]

    @staticmethod
    def _markdown_to_html(markdown: str) -> str:
        blocks: list[str] = ["<main class='report-document'>"]
        in_list = False
        in_section = False
        in_subsection = False
        seen_section = False

        def close_list() -> None:
            nonlocal in_list
            if in_list:
                blocks.append("</ul>")
                in_list = False

        def close_subsection() -> None:
            nonlocal in_subsection
            if in_subsection:
                blocks.append("</div>")
                in_subsection = False

        def close_section() -> None:
            nonlocal in_section
            if in_section:
                blocks.append("</section>")
                in_section = False

        for raw in markdown.splitlines():
            line = raw.strip()
            if not line:
                close_list()
                continue
            safe = html.escape(line)
            if line.startswith("### "):
                close_list()
                close_subsection()
                blocks.append("<div class='report-subsection'>")
                blocks.append(f"<h3>{html.escape(line[4:])}</h3>")
                in_subsection = True
            elif line.startswith("## "):
                close_list()
                close_subsection()
                close_section()
                blocks.append("<section class='report-section'>")
                blocks.append(f"<h2>{html.escape(line[3:])}</h2>")
                in_section = True
                seen_section = True
            elif line.startswith("# "):
                close_list()
                blocks.append(
                    "<header class='report-hero'><p>SHIELDCHAIN · AUTONOMOUS SOC</p>"
                    f"<h1>{html.escape(line[2:])}</h1></header>"
                )
            elif line.startswith("- "):
                if not in_list:
                    css_class = "report-list" if seen_section else "report-meta"
                    blocks.append(f"<ul class='{css_class}'>")
                    in_list = True
                blocks.append(f"<li>{html.escape(line[2:])}</li>")
            else:
                close_list()
                blocks.append(f"<p>{safe}</p>")
        close_list()
        close_subsection()
        close_section()
        blocks.append("</main>")
        body = "\n".join(blocks)
        document = (
            "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>ShieldChain 安全运营闭环报告</title><style>"
            "*{box-sizing:border-box}body{margin:0;background:#eef6fb;color:#102a43;"
            "font-family:Inter,system-ui,'Microsoft YaHei',sans-serif;line-height:1.68}"
            ".report-document{width:min(1120px,calc(100% - 40px));margin:32px auto 80px}"
            ".report-hero{position:relative;overflow:hidden;padding:44px 48px;border-radius:20px;"
            "color:#fff;background:linear-gradient(135deg,#072f4f,#087aa8);"
            "box-shadow:0 18px 50px rgba(5,61,94,.22)}"
            ".report-hero:after{content:'';position:absolute;width:260px;height:260px;"
            "right:-80px;top:-110px;border:42px solid rgba(255,255,255,.09);border-radius:50%}"
            ".report-hero p{margin:0 0 10px;letter-spacing:.18em;font-size:12px;font-weight:800;"
            "color:#9ee8ff}.report-hero h1{position:relative;z-index:1;margin:0;"
            "max-width:780px;font-size:clamp(28px,4vw,44px);line-height:1.2}"
            ".report-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;"
            "margin:18px 0;padding:20px 24px;list-style:none;border:1px solid #c9e3f3;"
            "border-radius:16px;background:#fff;box-shadow:0 8px 24px rgba(11,83,124,.07)}"
            ".report-meta li{padding:7px 10px;border-left:3px solid #4aafd5;overflow-wrap:anywhere}"
            ".report-section{margin-top:18px;padding:26px 30px;border:1px solid #c9e3f3;"
            "border-radius:16px;background:#fff;box-shadow:0 8px 24px rgba(11,83,124,.07)}"
            ".report-section h2{margin:0 0 18px;padding-bottom:12px;"
            "border-bottom:1px solid #d9ebf6;"
            "color:#063f68;font-size:22px}.report-section>p{color:#45647a}"
            ".report-list{margin:10px 0;padding-left:22px}.report-list li{margin:7px 0;"
            "padding-left:4px;overflow-wrap:anywhere}.report-list li::marker{color:#168bb8}"
            ".report-subsection{margin:14px 0;padding:16px 18px;border-left:4px solid #1595c2;"
            "border-radius:0 12px 12px 0;background:#f2f9fd}"
            ".report-subsection h3{margin:0 0 8px;color:#07577e;font-size:17px}"
            ".report-subsection .report-list{margin-bottom:0}"
            "@media(max-width:700px){.report-document{width:min(100% - 20px,1120px);"
            "margin-top:10px}"
            ".report-hero{padding:30px 24px}.report-meta{grid-template-columns:1fr;padding:16px}"
            ".report-section{padding:21px 18px}}"
            "@media print{body{background:#fff}.report-document{width:100%;margin:0}"
            ".report-hero,.report-meta,.report-section{box-shadow:none;break-inside:avoid}"
            ".report-section{border-color:#b8cbd7}}"
            "</style></head><body>"
            f"{body}</body></html>"
        )
        return SecurityOperationsReportAgent._with_assistant_launcher(document)

    @staticmethod
    def _with_assistant_launcher(document: str) -> str:
        if 'data-shieldchain-assistant-launcher="true"' in document:
            return document
        launcher = (
            '<a data-shieldchain-assistant-launcher="true" href="/assistant" target="_blank" '
            'rel="noreferrer" aria-label="在新窗口打开智能助手" style="position:fixed;'
            'right:20px;bottom:20px;z-index:99;display:inline-flex;align-items:center;gap:8px;'
            'padding:12px 18px;border:1px solid rgba(255,255,255,.55);border-radius:999px;'
            'color:#fff;background:linear-gradient(135deg,#075d8d,#128ab5);'
            'box-shadow:0 12px 30px rgba(6,73,112,.3);font-weight:700;text-decoration:none">'
            '<span aria-hidden="true" style="font-size:20px">✦</span><span>智能助手</span></a>'
        )
        return document.replace("</body>", f"{launcher}</body>", 1)
