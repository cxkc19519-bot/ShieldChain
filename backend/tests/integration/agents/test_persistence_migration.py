from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url

DEMO_TENANT = "00000000-0000-4000-8000-000000000001"
AGENT_TABLES = {
    "case_contexts",
    "confirmed_case_facts",
    "agent_private_contexts",
    "agent_handoffs",
    "agent_executions",
}
OTHER_TENANT = "00000000-0000-4000-8000-000000000099"


def test_sqlite_enforces_every_composite_tenant_boundary() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    tables = Base.metadata.tables
    now = datetime(2026, 7, 20, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            tables["simulation_instances"].insert(),
            {
                "id": "s",
                "scenario_key": "phishing",
                "generation": 1,
                "environment": "simulation",
                "connection_status": "active",
                "firewall_status": "not_blocked",
                "fail_block_consumed": False,
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            tables["incidents"].insert(),
            {
                "id": "i",
                "tenant_id": DEMO_TENANT,
                "external_id": "INC",
                "simulation_instance_id": "s",
                "alert_id": "ALT",
                "alert_status": "open",
                "endpoint": "host",
                "username": "user",
                "source_ip": "10.0.0.1",
                "remote_ip": "203.0.113.1",
                "remote_port": 443,
                "process_name": "p",
                "parent_process_name": "pp",
                "command_summary": "cmd",
                "threat_label": "threat",
                "created_at": now,
            },
        )

    run_values = {
        "id": "r",
        "incident_id": "i",
        "simulation_instance_id": "s",
        "status": "pending",
        "mode": "normal",
        "created_at": now,
        "updated_at": now,
    }
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            tables["investigation_runs"].insert(),
            {**run_values, "tenant_id": OTHER_TENANT},
        )
    with engine.begin() as connection:
        connection.execute(
            tables["investigation_runs"].insert(),
            {**run_values, "tenant_id": DEMO_TENANT},
        )

    case_values = {
        "id": "case",
        "run_id": "r",
        "revision": 0,
        "phase": "triage",
        "user_goal": "investigate",
        "hypotheses_json": [],
        "risks_json": [],
        "plan_json": [],
        "step_status_json": {},
        "disposition_status": "open",
        "budget_json": {},
        "created_at": now,
        "updated_at": now,
    }
    child_rows = {
        "case_contexts": case_values,
        "agent_private_contexts": {
            "id": "private",
            "run_id": "r",
            "role": "alert_triage",
            "revision": 0,
            "working_items_json": {},
            "references_json": [],
            "created_at": now,
            "updated_at": now,
        },
        "agent_handoffs": {
            "id": "handoff",
            "run_id": "r",
            "sender_role": "alert_triage",
            "receiver_role": "threat_investigation",
            "conclusion": "claim",
            "references_json": [],
            "confidence": 0.5,
            "open_questions_json": [],
            "recommended_actions_json": ["review"],
            "created_at": now,
        },
        "agent_executions": {
            "id": "execution",
            "run_id": "r",
            "role": "alert_triage",
            "summary": "summary",
            "references_json": [],
            "hypotheses_json": [],
            "risks_json": [],
            "recommended_actions_json": [],
            "termination_reason": "completed",
            "created_at": now,
        },
    }
    for table_name, values in child_rows.items():
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                tables[table_name].insert(),
                {**values, "tenant_id": OTHER_TENANT},
            )

    with engine.begin() as connection:
        connection.execute(
            tables["case_contexts"].insert(),
            {**case_values, "tenant_id": DEMO_TENANT},
        )
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            tables["confirmed_case_facts"].insert(),
            {
                "id": "fact",
                "case_context_id": "case",
                "tenant_id": OTHER_TENANT,
                "statement": "confirmed",
                "confirmed": True,
                "references_json": [{"id": "evidence"}],
                "confidence": 1.0,
                "confirmed_at": now,
                "created_at": now,
            },
        )


def _alembic(repository_root: Path, database_path: Path, *arguments: str) -> None:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(repository_root / "backend" / "alembic.ini"),
            *arguments,
        ],
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


def test_old_simulation_rows_are_backfilled_and_round_trip(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "phase4-migration.db"
    _alembic(root, database, "upgrade", "20260718_03")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO simulation_instances VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "s",
                "phishing",
                1,
                "simulation",
                "active",
                "not_blocked",
                0,
                "2026-07-20",
                "2026-07-20",
            ),
        )
        connection.execute(
            "INSERT INTO incidents "
            "(id,external_id,simulation_instance_id,alert_id,alert_status,endpoint,username,"
            "source_ip,remote_ip,remote_port,process_name,parent_process_name,command_summary,"
            "threat_label,next_audit_sequence,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "i",
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
                "2026-07-20",
            ),
        )
        connection.execute(
            "INSERT INTO investigation_runs "
            "(id,incident_id,simulation_instance_id,status,mode,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("r", "i", "s", "pending", "normal", "2026-07-20", "2026-07-20"),
        )
        connection.execute(
            "INSERT INTO investigation_steps VALUES (?,?,?,?,?,?,?,?)",
            ("step", "r", "collect", "succeeded", "{}", None, "2026-07-20", "2026-07-20"),
        )
        connection.execute(
            "INSERT INTO evidence_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "evidence",
                "r",
                "endpoint",
                "simulation",
                "2026-07-20",
                "summary",
                "object://evidence",
                "a" * 64,
                1.0,
                1,
                "{}",
                "2026-07-20",
            ),
        )
        connection.execute(
            "INSERT INTO simulation_tool_calls "
            "(id,run_id,simulation_instance_id,tool_name,target,idempotency_key,status,"
            "before_state_json,after_state_json,error_code,requested_at,completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "tool",
                "r",
                "s",
                "block_ip",
                "203.0.113.1",
                "key",
                "blocked",
                "{}",
                "{}",
                None,
                "2026-07-20",
                "2026-07-20",
            ),
        )
        connection.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?)",
            ("audit", "i", "r", 1, "run_created", "request", "2026-07-20", "{}"),
        )
        connection.commit()

    _alembic(root, database, "upgrade", "head")
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT tenant_id FROM incidents").fetchone() == (DEMO_TENANT,)
        assert connection.execute(
            "SELECT tenant_id FROM investigation_runs"
        ).fetchone() == (DEMO_TENANT,)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert AGENT_TABLES <= tables
        assert connection.execute(
            "SELECT count(*) FROM investigation_runs r LEFT JOIN incidents i "
            "ON i.id=r.incident_id AND i.tenant_id=r.tenant_id WHERE i.id IS NULL"
        ).fetchone() == (0,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for table_name in (
            "investigation_steps",
            "evidence_records",
            "simulation_tool_calls",
            "audit_events",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table_name}").fetchone() == (1,)

    _alembic(root, database, "downgrade", "20260718_03")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert AGENT_TABLES.isdisjoint(tables)
        assert "tenant_id" not in {
            row[1] for row in connection.execute("PRAGMA table_info(incidents)")
        }
        assert connection.execute("SELECT id FROM incidents").fetchone() == ("i",)
        assert connection.execute("SELECT id FROM investigation_runs").fetchone() == ("r",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for table_name in (
            "investigation_steps",
            "evidence_records",
            "simulation_tool_calls",
            "audit_events",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table_name}").fetchone() == (1,)

    _alembic(root, database, "upgrade", "head")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for table_name in (
            "investigation_steps",
            "evidence_records",
            "simulation_tool_calls",
            "audit_events",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table_name}").fetchone() == (1,)
