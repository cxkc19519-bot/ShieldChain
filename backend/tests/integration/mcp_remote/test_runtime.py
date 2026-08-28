import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import select

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.mcp_remote.peer_config import McpRemoteConfig
from shieldchain.mcp_remote.persistence import (
    AgentRunMcpSnapshotRow,
    McpSnapshotStore,
    McpToolSnapshot,
)
from shieldchain.mcp_remote.runtime import McpRemoteRuntime
from shieldchain.operations.schemas import AgentRoleRunView, OperationsReportRequest
from shieldchain.operations.service import OperationsReportStore, SecurityOperationsReportAgent

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


def _config() -> McpRemoteConfig:
    return McpRemoteConfig.model_validate(
        {
            "version": 1,
            "servers": [
                {
                    "id": "approved-peer",
                    "enabled": True,
                    "transport": "streamable_http",
                    "endpoint": "https://security.example.test/mcp",
                    "auth": {"mode": "bearer_env", "token_env": "REMOTE_MCP_TOKEN"},
                    "network_policy": "public_https",
                    "allowed_tools": [
                        {
                            "remote_name": "alerts_list",
                            "alias": "external.approved.alerts.list",
                            "schema_revision": "approved-v1",
                            "classification": "read_only",
                            "allowed_roles": ["alert_triage"],
                        }
                    ],
                }
            ],
        }
    )


def test_runtime_pins_only_latest_usable_accepted_snapshot(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'runtime.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = McpSnapshotStore(factory)
    store.save_accepted(
        peer_id="approved-peer",
        endpoint="https://security.example.test/mcp",
        network_policy="public_https",
        protocol_version="2026-07-28",
        catalog_revision="peer-catalog-v1",
        discovered_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        tools=(
            McpToolSnapshot(
                tool_identity=UUID("00000000-0000-4000-8000-000000009001"),
                remote_name="alerts_list",
                alias="external.approved.alerts.list",
                label="Remote title",
                description="Untrusted description",
                classification="read_only",
                allowed_roles=("alert_triage",),
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                remote_annotations={"destructiveHint": True},
                schema_revision="approved-v1",
            ),
        ),
    )
    runtime = McpRemoteRuntime(store, _config(), Settings(_env_file=None))

    catalog = runtime.prepare_run(now=NOW + timedelta(minutes=1))
    assert catalog.catalog_revision != "builtin-read-only-v1"
    assert len(catalog.tools) == 1
    assert catalog.tools[0].name == "external.approved.alerts.list"
    assert catalog.bindings[0].catalog_revision == "peer-catalog-v1"

    store.save_rejected(
        peer_id="approved-peer",
        endpoint="https://security.example.test/mcp",
        network_policy="public_https",
        error_code="mcp_schema_changed",
        now=NOW + timedelta(minutes=2),
    )
    blocked = runtime.prepare_run(now=NOW + timedelta(minutes=3))
    assert blocked.tools == ()
    assert blocked.bindings == ()
    assert blocked.catalog_revision == "builtin-read-only-v1"
    engine.dispose()


def test_operations_run_persists_selected_peer_snapshot_revision(
    tmp_path: Path, monkeypatch
) -> None:
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return (NOW + timedelta(minutes=1)).astimezone(tz)

    monkeypatch.setattr("shieldchain.operations.service.datetime", FrozenDatetime)
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'run-binding.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = McpSnapshotStore(factory)
    snapshot_id = store.save_accepted(
        peer_id="approved-peer",
        endpoint="https://security.example.test/mcp",
        network_policy="public_https",
        protocol_version="2026-07-28",
        catalog_revision="peer-catalog-v1",
        discovered_at=NOW,
        expires_at=NOW + timedelta(days=1),
        tools=(
            McpToolSnapshot(
                tool_identity=UUID("00000000-0000-4000-8000-000000009001"),
                remote_name="alerts_list",
                alias="external.approved.alerts.list",
                label="Remote title",
                description="Untrusted description",
                classification="read_only",
                allowed_roles=("alert_triage",),
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                remote_annotations={},
                schema_revision="approved-v1",
            ),
        ),
    )
    settings = Settings(_env_file=None, assistant_data_root=tmp_path / "assistant")
    runtime = McpRemoteRuntime(store, _config(), settings)
    agent = SecurityOperationsReportAgent(
        factory,
        settings=settings,
        tenant_id=settings.rag_demo_tenant_id,
        principal_id=settings.rag_demo_principal_id,
        store=OperationsReportStore(tmp_path / "reports"),
        knowledge=object(),
        remote_runtime=runtime,
    )
    captured_tools = []

    async def team_run(tools, *_args, **kwargs):
        captured_tools.extend(tools)
        plan_result = await agent._response_plan_agent.generate(
            run_id=kwargs["run_id"],
            public_handoffs=[],
            observation_summaries="尚未调用运营数据工具。",
            now=kwargs["now"],
        )
        return (
            [
                AgentRoleRunView(
                    role="response_planning",
                    label="响应规划智能体",
                    status="fallback",
                    summary=plan_result.reference.public_summary,
                    response_plan=plan_result.reference,
                )
            ],
            None,
            [],
        )

    async def synthesize(*_args):
        return "保守摘要", None, True

    agent._team.run = team_run
    agent._synthesize = synthesize
    report = asyncio.run(
        agent.generate(
            OperationsReportRequest(
                start_at=NOW,
                end_at=NOW + timedelta(minutes=5),
            )
        )
    )

    assert any(tool.name == "external.approved.alerts.list" for tool in captured_tools)
    with factory() as session:
        run = session.get(AgentRunRow, str(report.run_id))
        binding = session.scalar(select(AgentRunMcpSnapshotRow))
        assert run is not None and run.catalog_revision != "builtin-read-only-v1"
        assert binding is not None
        assert binding.peer_snapshot_id == str(snapshot_id)
        assert binding.catalog_revision == "peer-catalog-v1"
    engine.dispose()
