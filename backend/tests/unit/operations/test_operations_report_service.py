from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from shieldchain.core.config import Settings
from shieldchain.operations import service as service_module
from shieldchain.operations.react_collaboration import (
    _SPECIALISTS,
    AgentToolBroker,
    RealDataAgentTeam,
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


class FailingTool:
    name = "security.alerts.list"
    label = "告警 MCP"

    def __init__(self) -> None:
        self.calls = 0

    def call(self, _start_at: datetime, _end_at: datetime) -> McpToolCallView:
        self.calls += 1
        raise RuntimeError("private dependency detail")


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
    broker = AgentToolBroker(tools, start_at, start_at)
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

    requests: list[tuple[str, str]] = []

    async def chat(system, user, **_kwargs):
        requests.append((system, user))
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
    first_request = json.loads(requests[0][1])
    alert_tool = next(
        item for item in first_request["available_tools"] if item["name"] == "security.alerts.list"
    )
    assert alert_tool["description"]
    assert alert_tool["use_when"]
    assert alert_tool["do_not_use_when"]
    assert alert_tool["limitations"]
    assert "选择工具前必须阅读" in requests[0][0]


def test_tool_catalog_gives_model_usage_and_evidence_boundaries() -> None:
    tools = _tools()
    start_at = datetime(2026, 8, 1, tzinfo=UTC)
    broker = AgentToolBroker(tools, start_at, start_at)

    catalog = broker.catalog(_SPECIALISTS["threat_investigation"].allowed_tools)

    assert [item["name"] for item in catalog] == [
        "security.events.list",
        "security.alerts.list",
        "security.vulnerabilities.list",
        "security.weak_passwords.list",
    ]
    for item in catalog:
        assert item["label"]
        assert item["description"]
        assert item["use_when"]
        assert item["do_not_use_when"]
        assert item["parameters"]
        assert item["returns"]
        assert item["limitations"]

    vulnerability = next(
        item for item in catalog if item["name"] == "security.vulnerabilities.list"
    )
    assert "不等同于资产版本已确认受影响" in vulnerability["limitations"]


def test_rag_catalog_explains_query_and_does_not_expose_unallowed_tools() -> None:
    start_at = datetime(2026, 8, 1, tzinfo=UTC)
    broker = AgentToolBroker((), start_at, start_at)

    catalog = broker.catalog(_SPECIALISTS["knowledge_retrieval"].allowed_tools)

    assert [item["name"] for item in catalog] == ["knowledge.rag.retrieve"]
    assert "query" in catalog[0]["parameters"]
    assert "当前事件的已确认事实" in catalog[0]["do_not_use_when"]


@pytest.mark.parametrize(
    ("start_at", "end_at"),
    [
        (datetime(2026, 8, 1), datetime(2026, 8, 2)),
        (datetime(2026, 8, 2, tzinfo=UTC), datetime(2026, 8, 1, tzinfo=UTC)),
        (
            datetime(2026, 8, 1, tzinfo=UTC),
            datetime(2026, 8, 1, tzinfo=UTC) + timedelta(days=31, seconds=1),
        ),
    ],
)
def test_agent_tool_broker_rejects_invalid_time_windows(
    start_at: datetime, end_at: datetime
) -> None:
    with pytest.raises(ValueError):
        AgentToolBroker((), start_at, end_at)


def test_agent_tool_broker_caches_sanitized_failure() -> None:
    tool = FailingTool()
    now = datetime(2026, 8, 1, tzinfo=UTC)
    broker = AgentToolBroker((tool,), now, now)

    first = asyncio.run(broker.call(tool.name))
    second = asyncio.run(broker.call(tool.name))

    assert first is second
    assert first.status == "failed"
    assert first.reason_code == "tool_dependency_failed"
    assert first.result_count == 0
    assert first.items == []
    assert "private dependency detail" not in first.summary
    assert tool.calls == 1


def test_failed_tool_is_not_analyzed_as_zero_risk() -> None:
    failed = McpToolCallView(
        name="security.alerts.list",
        label="告警 MCP",
        status="failed",
        reason_code="tool_dependency_failed",
        arguments={
            "start_at": "2026-08-01T00:00:00+00:00",
            "end_at": "2026-08-02T00:00:00+00:00",
            "limit": 50,
        },
        result_count=0,
        summary="告警工具调用失败；未取得可信结果，需人工复核。",
        items=[],
    )

    analysis = SecurityOperationsReportAgent._analyze([failed])

    assert analysis["failed_tools"] == ["security.alerts.list"]
    assert "不能据此判定无风险" in str(analysis["summary"])


def test_synthesis_prompt_is_adapted_to_shieldchain_capabilities(
    tmp_path: Path, monkeypatch
) -> None:
    captured = {}

    class FakeClient:
        def __init__(self, _settings, _client) -> None:
            pass

        async def chat(self, request):
            captured["system"] = request.messages[0].content
            return SimpleNamespace(
                content="概括总结：存在待复核线索。\n\n处置建议：人工补充证据。",
                model="local-qwen",
            )

    monkeypatch.setattr(service_module, "DeepSeekClient", FakeClient)
    agent = SecurityOperationsReportAgent(
        None,  # type: ignore[arg-type]
        settings=Settings(_env_file=None, deepseek_api_key="local-vllm"),
        tenant_id=UUID("00000000-0000-4000-8000-000000000001"),
        store=OperationsReportStore(tmp_path),
        knowledge=None,  # type: ignore[arg-type]
        principal_id=UUID("00000000-0000-4000-8000-000000000002"),
        tools=(),
    )

    synthesis, model, fallback = asyncio.run(
        agent._synthesize(
            datetime(2026, 8, 1, tzinfo=UTC),
            datetime(2026, 8, 2, tzinfo=UTC),
            [],
            agent._analyze([]),
        )
    )

    prompt = captured["system"]
    assert "网络安全运营报告分析专家" in prompt
    assert "Wazuh 终端日志" in prompt
    assert "NTA 网络流量" in prompt
    assert "本地 RAG" in prompt
    assert "人工复核" in prompt
    assert "不得声称已自动封禁" in prompt
    assert synthesis.startswith("概括总结：")
    assert model == "local-qwen"
    assert fallback is False
