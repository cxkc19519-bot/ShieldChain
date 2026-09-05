from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import ForeignKeyConstraint, select

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.core.config import get_settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.operations.audit import AgentToolAuditContext, AgentToolAuditStore
from shieldchain.operations.mcp_tools import AgentToolExecutionResult
from shieldchain.operations.persistence import AgentToolCallRow
from shieldchain.operations.react_collaboration import AgentToolBroker
from shieldchain.operations.schemas import McpToolCallView

TENANT = UUID("00000000-0000-4000-8000-000000000001")
PRINCIPAL = UUID("00000000-0000-4000-8000-000000000002")
RUN = UUID("00000000-0000-4000-8000-000000000101")
NOW = datetime(2026, 8, 23, 2, tzinfo=UTC)


class AuditedTool:
    identity = UUID("00000000-0000-4000-8000-000000001001")
    name = "security.alerts.list"
    label = "告警工具"
    provider_kind = "builtin"
    provider_id = "shieldchain.operations"
    catalog_revision = "builtin-read-only-v1"
    schema_revision = "operations-time-window-v1"

    def call(self, start_at: datetime, end_at: datetime) -> McpToolCallView:
        return McpToolCallView(
            name=self.name,
            label=self.label,
            status="succeeded",
            arguments={
                "start_at": start_at.isoformat(),
                "end_at": end_at.isoformat(),
                "limit": 50,
            },
            result_count=1,
            summary="发现 1 条公开告警线索。",
            items=["公开告警"],
        )


class SecretFailingTool(AuditedTool):
    def call(self, _start_at: datetime, _end_at: datetime) -> McpToolCallView:
        raise RuntimeError("Authorization: Bearer private-token database=/private/path")


class RemoteAuditedTool(AuditedTool):
    identity = UUID("00000000-0000-4000-8000-000000001099")
    name = "external.approved.alerts.list"
    label = name
    provider_kind = "remote_mcp"
    provider_id = "approved-peer"
    catalog_revision = "remote-catalog-v1"
    schema_revision = "approved-v1"
    allowed_roles = ("alert_triage",)
    catalog_entry = {"label": label, "description": "Approved remote read-only data."}

    async def call(self, start_at: datetime, end_at: datetime) -> AgentToolExecutionResult:
        return AgentToolExecutionResult(
            view=McpToolCallView(
                name=self.name,
                label=self.label,
                status="succeeded",
                arguments={
                    "start_at": start_at.isoformat(),
                    "end_at": end_at.isoformat(),
                    "limit": 50,
                },
                result_count=1,
                summary="远程公开线索。",
                items=["公开线索"],
            ),
            result_bytes=1234,
            truncated=True,
        )


@pytest.fixture
def audit_store(tmp_path: Path):
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'agent-tool-audit.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        session.add(
            AgentRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                principal_id=str(PRINCIPAL),
                run_kind="operations_report",
                status="running",
                goal="audit test",
                catalog_revision="builtin-read-only-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    yield AgentToolAuditStore(factory), factory
    engine.dispose()


@pytest.mark.parametrize(
    ("direction", "run_id", "role"),
    [
        ("internal", RUN, "alert_triage"),
        ("mcp_inbound", None, None),
        ("mcp_outbound", RUN, "threat_investigation"),
    ],
)
def test_broker_persists_three_directions_with_public_fields_only(
    audit_store, direction: str, run_id: UUID | None, role: str | None
) -> None:
    store, factory = audit_store
    context = AgentToolAuditContext(
        tenant_id=TENANT,
        principal_id=PRINCIPAL,
        direction=direction,
        request_id=f"request-{direction}",
        run_id=run_id,
    )
    broker = AgentToolBroker(
        (AuditedTool(),),
        NOW,
        NOW,
        audit_store=store,
        audit_context=context,
    )

    result = asyncio.run(broker.call("security.alerts.list", role=role))

    assert result.status == "succeeded"
    with factory() as session:
        row = session.scalar(
            select(AgentToolCallRow).where(AgentToolCallRow.direction == direction)
        )
        assert row is not None
        assert row.run_id == (str(run_id) if run_id else None)
        assert row.role == role
        assert row.status == "succeeded"
        assert row.result_count == 1
        assert row.summary == "发现 1 条公开告警线索。"
        assert row.arguments_json == {
            "start_at": NOW.isoformat(),
            "end_at": NOW.isoformat(),
            "limit": 50,
        }
        assert row.duration_ms is not None and row.duration_ms >= 0
        assert row.result_bytes is not None and row.result_bytes > 0
        assert row.finished_at is not None


def test_failure_audit_does_not_persist_private_exception_material(audit_store) -> None:
    store, factory = audit_store
    context = AgentToolAuditContext(
        tenant_id=TENANT,
        principal_id=PRINCIPAL,
        direction="internal",
        request_id="request-secret-failure",
        run_id=RUN,
    )
    broker = AgentToolBroker(
        (SecretFailingTool(),),
        NOW,
        NOW,
        audit_store=store,
        audit_context=context,
    )

    result = asyncio.run(broker.call("security.alerts.list", role="alert_triage"))

    assert result.status == "failed"
    with factory() as session:
        row = session.scalar(select(AgentToolCallRow))
        assert row is not None
        persisted = repr(
            {
                column.name: getattr(row, column.name)
                for column in AgentToolCallRow.__table__.columns
            }
        )
        assert "private-token" not in persisted
        assert "/private/path" not in persisted
        assert row.status == "failed"
        assert row.reason_code == "tool_dependency_failed"


def test_remote_async_tool_uses_dynamic_role_catalog_and_outbound_audit(audit_store) -> None:
    store, factory = audit_store
    broker = AgentToolBroker(
        (RemoteAuditedTool(),),
        NOW,
        NOW,
        audit_store=store,
        audit_context=AgentToolAuditContext(
            tenant_id=TENANT,
            principal_id=PRINCIPAL,
            direction="internal",
            request_id="remote-outbound",
            run_id=RUN,
        ),
    )

    available = broker.available_for_role("alert_triage", (), set())
    assert available == ("external.approved.alerts.list",)
    assert broker.available_for_role("verification", (), set()) == ()
    assert broker.catalog(available)[0]["description"] == "Approved remote read-only data."
    with pytest.raises(ValueError, match="not allowed"):
        asyncio.run(broker.call(available[0], role="verification"))
    result = asyncio.run(broker.call(available[0], role="alert_triage"))
    assert result.status == "succeeded"

    with factory() as session:
        row = session.scalar(select(AgentToolCallRow))
        assert row is not None
        assert row.direction == "mcp_outbound"
        assert row.provider_kind == "remote_mcp"
        assert row.result_bytes == 1234
        assert row.truncated is True


def test_recovery_marks_interrupted_running_calls_unknown(audit_store) -> None:
    store, factory = audit_store
    call_id = store.start(
        AgentToolAuditContext(
            tenant_id=TENANT,
            principal_id=PRINCIPAL,
            direction="internal",
            request_id="request-interrupted",
            run_id=RUN,
        ),
        AuditedTool(),
        role="verification",
        arguments={"start_at": NOW.isoformat(), "end_at": NOW.isoformat(), "limit": 50},
        now=NOW,
    )

    assert store.recover_interrupted(now=NOW) == 1

    with factory() as session:
        row = session.get(AgentToolCallRow, str(call_id))
        assert row is not None
        assert row.status == "unknown"
        assert row.reason_code == "process_interrupted"
        assert row.summary == "工具调用在服务恢复时没有可信终态，结果未知，需人工复核。"
        assert row.finished_at.replace(tzinfo=UTC) == NOW


def test_agent_tool_call_metadata_has_bounded_contract() -> None:
    table = Base.metadata.tables["agent_tool_calls"]
    assert set(table.columns.keys()) == {
        "id",
        "tenant_id",
        "principal_id",
        "run_id",
        "case_id",
        "role",
        "direction",
        "provider_kind",
        "provider_id",
        "tool_identity",
        "tool_alias",
        "catalog_revision",
        "schema_revision",
        "arguments_json",
        "status",
        "reason_code",
        "result_count",
        "summary",
        "references_json",
        "duration_ms",
        "attempt",
        "result_bytes",
        "truncated",
        "request_id",
        "created_at",
        "finished_at",
    }
    assert table.c.run_id.nullable is True
    assert table.c.case_id.nullable is True
    assert table.c.role.nullable is True
    assert table.c.finished_at.nullable is True
    foreign_keys = {
        constraint.name: tuple(element.target_fullname for element in constraint.elements)
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }
    assert foreign_keys == {
        "fk_agent_tool_call_run_tenant": ("agent_runs.id", "agent_runs.tenant_id"),
        "fk_agent_tool_call_case_tenant": (
            "case_contexts.id",
            "case_contexts.tenant_id",
        ),
    }


def _migrate(
    root: Path,
    database: Path,
    target: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    configuration = Config(str(root / "backend" / "alembic.ini"))
    if target == "down":
        command.downgrade(configuration, "20260823_01")
    else:
        command.upgrade(configuration, target)
    get_settings.cache_clear()


def test_agent_tool_audit_migration_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "agent-tool-audit-migration.db"

    _migrate(root, database, "20260823_01", monkeypatch)
    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert "agent_tool_calls" in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    _migrate(root, database, "down", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert "agent_tool_calls" not in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260905_01",
        )


def test_agent_tool_audit_downgrade_refuses_to_drop_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "agent-tool-audit-downgrade-guard.db"
    _migrate(root, database, "head", monkeypatch)
    engine = create_engine_from_url(f"sqlite:///{database.as_posix()}")
    factory = create_session_factory(engine)
    with factory.begin() as session:
        session.add(
            AgentRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                principal_id=str(PRINCIPAL),
                run_kind="operations_report",
                status="running",
                goal="audit downgrade guard",
                catalog_revision="builtin-read-only-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    AgentToolAuditStore(factory).start(
        AgentToolAuditContext(
            tenant_id=TENANT,
            principal_id=PRINCIPAL,
            direction="internal",
            request_id="audit-downgrade-guard",
            run_id=RUN,
        ),
        AuditedTool(),
        role="verification",
        arguments={"start_at": NOW.isoformat(), "end_at": NOW.isoformat(), "limit": 50},
        now=NOW,
    )
    engine.dispose()

    with pytest.raises(RuntimeError, match="agent tool call audits exist"):
        _migrate(root, database, "down", monkeypatch)

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM agent_tool_calls").fetchone() == (1,)
