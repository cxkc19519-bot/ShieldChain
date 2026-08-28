from __future__ import annotations

import json
import re
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.wazuh.persistence import WazuhAlertRow, WazuhReviewCaseRow

from .schemas import McpToolCallView

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
_WEAK_PASSWORD = re.compile(
    r"weak\s*password|弱口令|password\s*spray|brute\s*force|暴力破解|密码喷洒",
    re.IGNORECASE,
)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _short(value: str, length: int = 120) -> str:
    normalized = " ".join(value.replace("\n", " ").split())
    return normalized[:length] + ("…" if len(normalized) > length else "")


def _behavior_categories(evidence: dict[str, object]) -> tuple[str, ...]:
    raw = evidence.get("behavior_findings")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return ()
    if not isinstance(raw, list):
        return ()
    categories = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "").strip()
        if category and category not in categories:
            categories.append(category)
    return tuple(categories[:5])


class ReadOnlyAgentTool(Protocol):
    identity: UUID
    name: str
    label: str
    provider_kind: str
    provider_id: str
    catalog_revision: str
    schema_revision: str

    def call(
        self, start_at: datetime, end_at: datetime
    ) -> McpToolCallView | AgentToolExecutionResult | Awaitable[AgentToolExecutionResult]: ...


@dataclass(frozen=True, slots=True)
class AgentToolExecutionResult:
    view: McpToolCallView
    result_bytes: int | None = None
    truncated: bool = False


# Kept for callers that still use the old façade name while the protocol adapter is introduced.
ReadOnlyMcpTool = ReadOnlyAgentTool


class _BaseWazuhTool:
    identity = UUID("00000000-0000-4000-8000-000000001000")
    name = ""
    label = ""
    provider_kind = "builtin"
    provider_id = "shieldchain.operations"
    catalog_revision = "builtin-read-only-v1"
    schema_revision = "operations-time-window-v1"

    def __init__(self, session_factory: sessionmaker[Session], tenant_id: UUID) -> None:
        self._session_factory = session_factory
        self._tenant_id = str(tenant_id)

    @staticmethod
    def _view(
        *,
        name: str,
        label: str,
        start_at: datetime,
        end_at: datetime,
        items: list[str],
        summary: str,
    ) -> McpToolCallView:
        return McpToolCallView(
            name=name,
            label=label,
            status="succeeded" if items else "empty",
            arguments={
                "start_at": _utc(start_at).isoformat(),
                "end_at": _utc(end_at).isoformat(),
                "limit": 50,
            },
            result_count=len(items),
            summary=summary,
            items=items,
        )


class EventMcpTool(_BaseWazuhTool):
    """Read-only MCP façade for review cases generated from incoming events."""

    identity = UUID("00000000-0000-4000-8000-000000001001")
    name = "security.events.list"
    label = "事件 MCP"

    def call(self, start_at: datetime, end_at: datetime) -> McpToolCallView:
        with self._session_factory() as session:
            rows = session.scalars(
                select(WazuhReviewCaseRow)
                .where(
                    WazuhReviewCaseRow.tenant_id == self._tenant_id,
                    WazuhReviewCaseRow.created_at >= start_at,
                    WazuhReviewCaseRow.created_at <= end_at,
                )
                .order_by(WazuhReviewCaseRow.severity.desc(), WazuhReviewCaseRow.created_at.desc())
                .limit(50)
            ).all()
        items = [
            (
                f"{row.tracking_year}-{row.tracking_sequence:04d}｜等级 "
                f"{row.severity}｜{_short(row.title)}"
            )
            for row in rows
        ]
        return self._view(
            name=self.name,
            label=self.label,
            start_at=start_at,
            end_at=end_at,
            items=items,
            summary=f"时间范围内发现 {len(items)} 个待人工复核事件。",
        )


class AlertMcpTool(_BaseWazuhTool):
    identity = UUID("00000000-0000-4000-8000-000000001002")
    name = "security.alerts.list"
    label = "告警 MCP"

    def call(self, start_at: datetime, end_at: datetime) -> McpToolCallView:
        with self._session_factory() as session:
            rows = session.scalars(
                select(WazuhAlertRow)
                .where(
                    WazuhAlertRow.tenant_id == self._tenant_id,
                    WazuhAlertRow.occurred_at >= start_at,
                    WazuhAlertRow.occurred_at <= end_at,
                )
                .order_by(WazuhAlertRow.severity.desc(), WazuhAlertRow.occurred_at.desc())
                .limit(50)
            ).all()
        items = []
        for row in rows:
            behaviors = _behavior_categories(row.evidence_json)
            behavior_text = f"｜行为 {', '.join(behaviors)}" if behaviors else ""
            items.append(
                f"等级 {row.severity}｜规则 {row.rule_id}｜{_short(row.title)}{behavior_text}"
            )
        critical = sum(1 for row in rows if row.severity >= 12)
        return self._view(
            name=self.name,
            label=self.label,
            start_at=start_at,
            end_at=end_at,
            items=items,
            summary=f"时间范围内接收 {len(items)} 条告警，其中 {critical} 条为高风险告警。",
        )


class VulnerabilityMcpTool(_BaseWazuhTool):
    identity = UUID("00000000-0000-4000-8000-000000001003")
    name = "security.vulnerabilities.list"
    label = "漏洞 MCP"

    def call(self, start_at: datetime, end_at: datetime) -> McpToolCallView:
        with self._session_factory() as session:
            rows = session.scalars(
                select(WazuhAlertRow)
                .where(
                    WazuhAlertRow.tenant_id == self._tenant_id,
                    WazuhAlertRow.occurred_at >= start_at,
                    WazuhAlertRow.occurred_at <= end_at,
                )
                .order_by(WazuhAlertRow.severity.desc(), WazuhAlertRow.occurred_at.desc())
                .limit(200)
            ).all()
        findings: list[str] = []
        seen: set[str] = set()
        for row in rows:
            source = f"{row.title}\n{json.dumps(row.evidence_json, ensure_ascii=False)}"
            for cve in _CVE.findall(source):
                normalized = cve.upper()
                if normalized in seen:
                    continue
                seen.add(normalized)
                findings.append(
                    f"{normalized}｜关联告警等级 {row.severity}｜{_short(row.title, 70)}"
                )
                if len(findings) == 50:
                    break
            if len(findings) == 50:
                break
        return self._view(
            name=self.name,
            label=self.label,
            start_at=start_at,
            end_at=end_at,
            items=findings,
            summary=(
                f"从告警标题和已规范化证据字段中识别出 {len(findings)} 个 CVE 标识；"
                "这不等同于资产已确认受影响，需结合资产版本复核。"
            ),
        )


class WeakPasswordMcpTool(_BaseWazuhTool):
    identity = UUID("00000000-0000-4000-8000-000000001004")
    name = "security.weak_passwords.list"
    label = "弱口令 MCP"

    def call(self, start_at: datetime, end_at: datetime) -> McpToolCallView:
        with self._session_factory() as session:
            rows = session.scalars(
                select(WazuhAlertRow)
                .where(
                    WazuhAlertRow.tenant_id == self._tenant_id,
                    WazuhAlertRow.occurred_at >= start_at,
                    WazuhAlertRow.occurred_at <= end_at,
                )
                .order_by(WazuhAlertRow.severity.desc(), WazuhAlertRow.occurred_at.desc())
                .limit(200)
            ).all()
        findings = []
        for row in rows:
            source = f"{row.title}\n{json.dumps(row.evidence_json, ensure_ascii=False)}"
            if _WEAK_PASSWORD.search(source):
                findings.append(f"等级 {row.severity}｜{_short(row.title)}")
                if len(findings) == 50:
                    break
        return self._view(
            name=self.name,
            label=self.label,
            start_at=start_at,
            end_at=end_at,
            items=findings,
            summary=(
                f"从本时间段告警元数据中发现 {len(findings)} 条弱口令或暴力破解线索。"
                "未发现不代表资产不存在弱口令。"
            ),
        )


def standard_agent_tools(
    session_factory: sessionmaker[Session], tenant_id: UUID
) -> tuple[ReadOnlyAgentTool, ...]:
    """Return the four internal read-only tools available to the report agent."""

    return (
        EventMcpTool(session_factory, tenant_id),
        AlertMcpTool(session_factory, tenant_id),
        VulnerabilityMcpTool(session_factory, tenant_id),
        WeakPasswordMcpTool(session_factory, tenant_id),
    )


standard_mcp_tools = standard_agent_tools
