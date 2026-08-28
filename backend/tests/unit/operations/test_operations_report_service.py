from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.operations import service as service_module
from shieldchain.operations.react_collaboration import (
    _SPECIALISTS,
    AgentToolBroker,
    RealDataAgentTeam,
)
from shieldchain.operations.schemas import (
    McpToolCallView,
    OperationsReportRequest,
    OperationsReportView,
)
from shieldchain.operations.service import OperationsReportStore, SecurityOperationsReportAgent


class FakeTool:
    identity = UUID("00000000-0000-4000-8000-000000009999")
    provider_kind = "builtin"
    provider_id = "test.operations"
    catalog_revision = "test-v1"
    schema_revision = "test-v1"

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
    identity = UUID("00000000-0000-4000-8000-000000009998")
    name = "security.alerts.list"
    label = "告警 MCP"
    provider_kind = "builtin"
    provider_id = "test.operations"
    catalog_revision = "test-v1"
    schema_revision = "test-v1"

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
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'operations-unit.db'}")
    Base.metadata.create_all(engine)
    agent = SecurityOperationsReportAgent(
        create_session_factory(engine),
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

    assert len(report.stages) == 7
    assert report.response_plan is not None
    assert report.response_plan.status == "completed_advisory"
    assert report.response_plan.execution_status == "not_executed"
    response_role = next(item for item in report.collaboration if item.role == "response_planning")
    assert response_role.response_plan is not None
    assert response_role.response_plan.plan_id == report.response_plan.plan_id
    assert {item.name for item in report.tool_calls} == {tool.name for tool in tools}
    assert all(tool.calls == 1 for tool in tools)
    assert "<script>" not in report.html
    assert "&lt;script&gt;" in report.html
    assert [step.phase for step in report.reasoning_trace[:2]] == ["observe", "correlate"]
    assert report.reasoning_trace[-1].phase == "close"
    assert {item.status for item in report.cross_domain} == {"observed", "not_observed"}
    knowledge_domain = next(item for item in report.cross_domain if item.key == "knowledge")
    assert knowledge_domain.status == "not_observed"
    assert report.closure.status == "analysis_complete"
    assert "尚未进入接受或审批流程" in report.closure.action
    assert "结构化推理链" in report.markdown
    assert agent.get(report.id) == report
    engine.dispose()


def test_legacy_report_without_run_id_is_explicit(tmp_path: Path) -> None:
    store = OperationsReportStore(tmp_path)
    path = tmp_path / "operations-reports" / "reports.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "OPS-LEGACY",
                    "generated_at": "2026-08-01T00:00:00Z",
                    "start_at": "2026-08-01T00:00:00Z",
                    "end_at": "2026-08-02T00:00:00Z",
                    "agent_name": "安全运营报告智能体",
                    "model": None,
                    "stages": [],
                    "collaboration": [],
                    "tool_calls": [],
                    "markdown": "legacy",
                    "html": "<p>legacy</p>",
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    report = store.list()[0]

    assert isinstance(report, OperationsReportView)
    assert report.run_id is None
    assert report.run_status == "legacy_without_run"
    assert report.response_plan is None


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


@pytest.mark.parametrize(
    ("observation", "status", "count"),
    [
        ("ATT&CK T1021 远程服务", "succeeded", 1),
        ("未检索到可引用片段。", "empty", 0),
        ("RAG 暂不可用；不得据此扩写事实。", "failed", 0),
    ],
)
def test_rag_observation_is_projected_into_cross_domain_trace(
    observation: str,
    status: str,
    count: int,
) -> None:
    team = _team(Settings(_env_file=None, deepseek_api_key="test-key"))
    broker = AgentToolBroker((), datetime(2026, 8, 1, tzinfo=UTC), datetime(2026, 8, 1, tzinfo=UTC))
    responses = iter(
        [
            {
                "action": "call_tool",
                "tool": "knowledge.rag.retrieve",
                "query": "ATT&CK lateral movement",
                "public_reason": "补充技战术依据",
            },
            {
                "action": "finish",
                "summary": "已获得可引用知识依据。",
                "public_reason": "知识依据已足够",
            },
        ]
    )

    async def chat(_system, _user, **_kwargs):
        return SimpleNamespace(
            content=json.dumps(next(responses), ensure_ascii=False), model="deepseek-test"
        )

    team._chat = chat  # type: ignore[method-assign]
    team._retrieve = lambda _query: observation  # type: ignore[method-assign]
    summary, model, _reason = asyncio.run(
        team._run_role(_SPECIALISTS["knowledge_retrieval"], broker, [])
    )

    assert "知识依据" in summary
    assert model == "deepseek-test"
    assert [item.name for item in broker.results] == ["knowledge.rag.retrieve"]
    assert broker.results[0].result_count == count
    assert broker.results[0].status == status
    if status == "failed":
        assert broker.results[0].reason_code == "tool_dependency_failed"


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
    assert analysis["observed_domains"] == []
    domains = SecurityOperationsReportAgent._cross_domain([failed])
    alert_domain = next(item for item in domains if item.key == "endpoint_detection")
    assert alert_domain.status == "not_observed"
    assert "调用失败" in alert_domain.summary
    trace = SecurityOperationsReportAgent._reasoning_trace(
        collaboration=[],
        tool_calls=[failed],
        analysis=analysis,
    )
    assert trace[0].status == "blocked"
    assert trace[0].confidence == 0
    assert trace[1].status == "pending"


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
