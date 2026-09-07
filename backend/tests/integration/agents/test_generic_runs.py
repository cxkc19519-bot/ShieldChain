from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import ForeignKeyConstraint, inspect
from sqlalchemy.orm import Session

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.core.config import get_settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url
from shieldchain.incidents.domain import InvestigationStatus, RunMode
from shieldchain.incidents.repositories import SqlAlchemyIncidentRepository
from shieldchain.incidents.scenario import seed_phishing_scenario

TENANT = "00000000-0000-4000-8000-000000000001"
PRINCIPAL = "00000000-0000-4000-8000-000000000002"
RUN = "00000000-0000-4000-8000-000000000101"
CASE = "00000000-0000-4000-8000-000000000102"
TOOL_CALL = "00000000-0000-4000-8000-000000000103"
LOOP = "00000000-0000-4000-8000-000000000104"


def _foreign_key_target(table_name: str, constraint_name: str) -> tuple[str, ...]:
    table = Base.metadata.tables[table_name]
    constraint = next(
        item
        for item in table.constraints
        if isinstance(item, ForeignKeyConstraint) and item.name == constraint_name
    )
    return tuple(element.target_fullname for element in constraint.elements)


def test_generic_run_tables_and_stage_four_to_six_foreign_keys_are_registered() -> None:
    assert set(Base.metadata.tables["agent_runs"].columns.keys()) == {
        "id",
        "tenant_id",
        "principal_id",
        "run_kind",
        "status",
        "goal",
        "catalog_revision",
        "revision",
        "created_at",
        "updated_at",
        "completed_at",
    }
    assert set(Base.metadata.tables["operations_runs"].columns.keys()) == {
        "run_id",
        "tenant_id",
        "start_at",
        "end_at",
        "report_id",
        "created_at",
    }
    expected = {
        ("investigation_runs", "fk_investigation_agent_run_tenant"),
        ("case_contexts", "fk_case_context_run_tenant"),
        ("agent_private_contexts", "fk_private_context_run_tenant"),
        ("agent_handoffs", "fk_agent_handoff_run_tenant"),
        ("agent_executions", "fk_agent_execution_run_tenant"),
        ("trusted_tool_calls", "fk_trusted_tool_call_run_tenant"),
        ("react_loops", "fk_react_loop_run_tenant"),
    }
    for table_name, constraint_name in expected:
        assert _foreign_key_target(table_name, constraint_name) == (
            "agent_runs.id",
            "agent_runs.tenant_id",
        )


def test_operations_run_can_own_agent_tool_and_react_children() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    tables = Base.metadata.tables
    now = datetime(2026, 8, 23, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            tables["agent_runs"].insert(),
            {
                "id": RUN,
                "tenant_id": TENANT,
                "principal_id": PRINCIPAL,
                "run_kind": "operations_report",
                "status": "running",
                "goal": "Generate a bounded security operations report.",
                "catalog_revision": "builtin-read-only-v1",
                "revision": 0,
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            tables["operations_runs"].insert(),
            {
                "run_id": RUN,
                "tenant_id": TENANT,
                "start_at": now,
                "end_at": now,
                "report_id": "OPS-20260823-TEST",
                "created_at": now,
            },
        )
        connection.execute(
            tables["case_contexts"].insert(),
            {
                "id": CASE,
                "run_id": RUN,
                "tenant_id": TENANT,
                "revision": 0,
                "phase": "triage",
                "user_goal": "Review security evidence.",
                "hypotheses_json": [],
                "risks_json": [],
                "plan_json": [],
                "step_status_json": {},
                "disposition_status": "open",
                "budget_json": {},
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            tables["trusted_tool_calls"].insert(),
            {
                "id": TOOL_CALL,
                "run_id": RUN,
                "tenant_id": TENANT,
                "case_id": CASE,
                "plan_id": "plan-1",
                "idempotency_key": "operations-test",
                "caller_role": "response_planning",
                "tool_name": "block_ip",
                "tool_version": "1",
                "arguments_json": {},
                "expected_state_json": {},
                "rollback_strategy": "manual",
                "evidence_json": [],
                "request_digest": "a" * 64,
                "status": "proposed",
                "revision": 0,
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            tables["react_loops"].insert(),
            {
                "id": LOOP,
                "run_id": RUN,
                "tenant_id": TENANT,
                "case_id": CASE,
                "status": "running",
                "revision": 0,
                "budget_json": {},
                "observation_fingerprints_json": [],
                "started_at": now,
                "updated_at": now,
            },
        )
    assert inspect(engine).has_table("operations_runs")
    engine.dispose()


def test_investigation_repository_keeps_generic_parent_status_in_sync() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    repository = SqlAlchemyIncidentRepository(seed_phishing_scenario)
    now = datetime(2026, 8, 23, tzinfo=UTC)
    with Session(engine) as session:
        scenario = repository.reset_phishing_scenario(session, now=now)
        run = repository.create_run(
            session,
            simulation_id=scenario.simulation_id,
            mode=RunMode.NORMAL,
            request_id="generic-run-test",
            now=now,
        )
        parent = session.get(AgentRunRow, str(run.id))
        assert parent is not None
        assert parent.status == "pending"
        repository.transition_run(
            session,
            run.id,
            InvestigationStatus.COLLECTING,
            request_id="generic-run-transition",
            now=now,
        )
        parent = session.get(AgentRunRow, str(run.id))
        assert parent is not None
        assert parent.status == "running"
        assert parent.revision == 1
        repository.mark_recoverable_runs_interrupted(
            session, request_id="generic-run-recovery", now=now
        )
        parent = session.get(AgentRunRow, str(run.id))
        assert parent is not None
        assert parent.status == "needs_review"
        assert parent.revision == 2
    engine.dispose()


def _migrate(root: Path, database: Path, target: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    configuration = Config(str(root / "backend" / "alembic.ini"))
    command.upgrade(configuration, target) if target != "down" else command.downgrade(
        configuration, "20260729_01"
    )
    get_settings.cache_clear()


def test_generic_run_migration_backfills_and_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "generic-runs.db"
    _migrate(root, database, "20260729_01", monkeypatch)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO simulation_instances "
            "(id,scenario_key,generation,environment,connection_status,firewall_status,"
            "fail_block_consumed,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "s",
                "phishing",
                1,
                "simulation",
                "active",
                "not_blocked",
                0,
                "2026-08-23",
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO incidents "
            "(id,tenant_id,external_id,simulation_instance_id,alert_id,alert_status,endpoint,"
            "username,source_ip,remote_ip,remote_port,process_name,parent_process_name,"
            "command_summary,threat_label,next_audit_sequence,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "i",
                TENANT,
                "INC",
                "s",
                "ALT",
                "open",
                "host",
                "user",
                "10.0.0.1",
                "203.0.113.1",
                443,
                "p",
                "pp",
                "cmd",
                "threat",
                1,
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO investigation_runs "
            "(id,tenant_id,incident_id,simulation_instance_id,status,mode,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("r", TENANT, "i", "s", "closed", "normal", "2026-08-23", "2026-08-23"),
        )
        connection.execute(
            "INSERT INTO case_contexts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "case",
                "r",
                TENANT,
                0,
                "triage",
                "legacy",
                "[]",
                "[]",
                "[]",
                "{}",
                "open",
                "{}",
                "2026-08-23",
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO agent_private_contexts VALUES (?,?,?,?,?,?,?,?,?)",
            ("private", "r", TENANT, "alert_triage", 0, "{}", "[]", "2026-08-23", "2026-08-23"),
        )
        connection.execute(
            "INSERT INTO agent_handoffs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "handoff",
                "r",
                TENANT,
                "alert_triage",
                "reporting",
                "legacy",
                "[]",
                1.0,
                "[]",
                "[]",
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO agent_executions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "execution",
                "r",
                TENANT,
                "alert_triage",
                "legacy",
                "[]",
                "[]",
                "[]",
                "[]",
                "completed",
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO trusted_tool_calls "
            "(id,run_id,tenant_id,case_id,plan_id,idempotency_key,caller_role,tool_name,"
            "tool_version,arguments_json,expected_state_json,rollback_strategy,evidence_json,"
            "request_digest,status,revision,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "tool",
                "r",
                TENANT,
                "case",
                "plan",
                "legacy",
                "response_planning",
                "block_ip",
                "1",
                "{}",
                "{}",
                "manual",
                "[]",
                "a" * 64,
                "proposed",
                0,
                "2026-08-23",
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO react_loops VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                "loop",
                TENANT,
                "case",
                "r",
                "running",
                0,
                "{}",
                "[]",
                "2026-08-23",
                "2026-08-23",
            ),
        )
        connection.commit()

    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT id,tenant_id,run_kind,status FROM agent_runs"
        ).fetchall() == [("r", TENANT, "incident_investigation", "completed")]
        for table_name in (
            "case_contexts",
            "agent_private_contexts",
            "agent_handoffs",
            "agent_executions",
            "trusted_tool_calls",
            "react_loops",
        ):
            assert "agent_runs" in {
                row[2] for row in connection.execute(f"PRAGMA foreign_key_list({table_name})")
            }
            assert connection.execute(f"SELECT count(*) FROM {table_name}").fetchone() == (1,)

    _migrate(root, database, "down", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT id FROM investigation_runs").fetchall() == [("r",)]
        for table_name in (
            "case_contexts",
            "agent_private_contexts",
            "agent_handoffs",
            "agent_executions",
            "trusted_tool_calls",
            "react_loops",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table_name}").fetchone() == (1,)
        assert "agent_runs" not in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM agent_runs").fetchone() == (1,)


def test_generic_run_downgrade_refuses_to_drop_operations_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "generic-runs-downgrade-guard.db"
    _migrate(root, database, "head", monkeypatch)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO agent_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                RUN,
                TENANT,
                PRINCIPAL,
                "operations_report",
                "completed",
                "report",
                "builtin-read-only-v1",
                1,
                "2026-08-23",
                "2026-08-23",
                "2026-08-23",
            ),
        )
        connection.execute(
            "INSERT INTO operations_runs VALUES (?,?,?,?,?,?)",
            (RUN, TENANT, "2026-08-22", "2026-08-23", "OPS-20260823-GUARD", "2026-08-23"),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="operations runs exist"):
        _migrate(root, database, "down", monkeypatch)

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT report_id FROM operations_runs").fetchone() == (
            "OPS-20260823-GUARD",
        )
