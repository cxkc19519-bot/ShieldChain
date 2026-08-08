from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from shieldchain.core.config import Settings
from shieldchain.operations.react_collaboration import (
    _SPECIALISTS,
    RealDataAgentTeam,
    _ToolBroker,
)
from shieldchain.operations.schemas import McpToolCallView, OperationsReportRequest
from shieldchain.operations.service import OperationsReportStore, SecurityOperationsReportAgent


class FakeTool:
    def __init__(self, name: str, label: str, items: list[str]) -> None:
        self.name = name
        self.label = label
        self.items = items
        self.calls = 0

    def call(self, start_at: datetime, end_at: datetime) -> McpToolCallView:
        self.calls += 1
        return McpToolCallView(
            name=self.name,
            label=self.label,
            status="succeeded" if self.items else "empty",
            arguments={"start_at": start_at.isoformat(), "end_at": end_at.isoformat(), "limit": 50},
            result_count=len(self.items),
            summary=f"{self.label} 返回 {len(self.items)} 项。",
            items=self.items,
        )


def _tools() -> tuple[FakeTool, ...]:
    return (
        FakeTool("security.events.list", "事件 MCP", ["事件-1"]),
        FakeTool("security.alerts.list", "告警 MCP", ["等级 12｜NTA 告警"]),
        FakeTool("security.vulnerabilities.list", "漏洞 MCP", ["CVE-2026-1234"]),
        FakeTool("security.weak_passwords.list", "弱口令 MCP", ["<script>alert(1)</script>"]),
    )


def _team(settings: Settings | None = None) -> RealDataAgentTeam:
    return RealDataAgentTeam(
        settings or Settings(_env_file=None),
        None,  # type: ignore[arg-type]
        tenant_id=UUID("00000000-0000-4000-8000-000000000001"),
        principal_id=UUID("00000000-0000-4000-8000-000000000002"),
    )


def test_report_agent_fallback_runs_safe_minimum_and_persists_html(tmp_path: Path) -> None:
    tools = _tools()
    agent = SecurityOperationsReportAgent(
        None,  # type: ignore[arg-type]
        settings=Settings(_env_file=None),
        tenant_id=UUID("00000000-0000-4000-8000-000000000001"),
        store=OperationsReportStore(tmp_path),
        knowledge=None,  # type: ignore[arg-type]
        principal_id=UUID("00000000-0000-4000-8000-000000000002"),
        tools=tools,
    )

    async def fallback(*_args):
        return "综合建议：先人工复核。", None, True

    agent._synthesize = fallback  # type: ignore[method-assign]
    report = asyncio.run(
        agent.generate(
            OperationsReportRequest(
                start_at=datetime(2026, 8, 1, tzinfo=UTC),
                end_at=datetime(2026, 8, 2, tzinfo=UTC),
            )
        )
    )

    assert len(report.stages) == 6
    assert {item.name for item in report.tool_calls} == {tool.name for tool in tools}
    assert all(tool.calls == 1 for tool in tools)
    assert "<script>" not in report.html
    assert "&lt;script&gt;" in report.html
    assert agent.get(report.id) == report


def test_react_superagent_controls_specialist_order() -> None:
    team = _team()
    decisions = iter(
        [
            "verification",
            "knowledge_retrieval",
            "alert_triage",
            "response_planning",
            "threat_investigation",
            "reporting",
        ]
    )

    async def choose(remaining, _facts, _results):
        role = next(decisions)
        assert role in remaining
        return role, f"选择 {role}", "deepseek-test"

    async def run_role(definition, _broker, _results):
        return f"{definition.label}完成", "deepseek-test", "工具决策：按需完成"

    team._choose = choose  # type: ignore[method-assign]
    team._run_role = run_role  # type: ignore[method-assign]
    start_at = datetime(2026, 8, 1, tzinfo=UTC)
    rows, model, calls = asyncio.run(team.run((), start_at, start_at))
    assert [item.role for item in rows] == [
        "superagent",
        "verification",
        "knowledge_retrieval",
        "alert_triage",
        "response_planning",
        "threat_investigation",
        "reporting",
    ]
    assert model == "deepseek-test"
    assert calls == []
    assert [item.iteration for item in rows] == list(range(1, 8))


def test_specialist_model_selects_only_needed_tool() -> None:
    team = _team(Settings(_env_file=None, deepseek_api_key="test-key"))
    tools = _tools()
    start_at = datetime(2026, 8, 1, tzinfo=UTC)
    broker = _ToolBroker(tools, start_at, start_at)
    responses = iter(
        [
            {
                "action": "call_tool",
                "tool": "security.alerts.list",
                "query": "",
                "public_reason": "先查看告警严重性",
            },
            {
                "action": "finish",
                "summary": "发现一条高等级告警，应优先人工复核。",
                "public_reason": "告警结果已经足够完成分诊",
            },
        ]
    )

    async def chat(*_args, **_kwargs):
        return SimpleNamespace(
            content=json.dumps(next(responses), ensure_ascii=False), model="deepseek-test"
        )

    team._chat = chat  # type: ignore[method-assign]
    summary, model, reason = asyncio.run(team._run_role(_SPECIALISTS["alert_triage"], broker, []))

    assert "高等级告警" in summary
    assert model == "deepseek-test"
    assert "先查看告警严重性" in reason
    assert [item.name for item in broker.results] == ["security.alerts.list"]
    assert tools[0].calls == 0
    assert tools[1].calls == 1
