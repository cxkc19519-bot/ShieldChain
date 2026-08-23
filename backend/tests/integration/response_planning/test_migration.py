import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from shieldchain.core.config import get_settings

TENANT = "00000000-0000-4000-8000-000000000001"
RUN = "00000000-0000-4000-8000-000000000101"
CALL = "00000000-0000-4000-8000-000000000102"
SECOND_CALL = "00000000-0000-4000-8000-000000000104"
CASE = "00000000-0000-4000-8000-000000000103"


def _configuration(root: Path, database: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    return Config(str(root / "backend" / "alembic.ini"))


def test_response_plan_migration_safely_backfills_legacy_tool_plan_and_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "response-plan-migration.db"
    configuration = _configuration(root, database, monkeypatch)
    command.upgrade(configuration, "20260823_04")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO agent_runs "
            "(id,tenant_id,principal_id,run_kind,status,goal,catalog_revision,revision,"
            "created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                RUN,
                TENANT,
                "00000000-0000-4000-8000-000000000002",
                "operations_report",
                "running",
                "legacy plan migration",
                "legacy-v1",
                0,
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO trusted_tool_calls "
            "(id,run_id,tenant_id,case_id,plan_id,idempotency_key,caller_role,tool_name,"
            "tool_version,arguments_json,expected_state_json,rollback_strategy,evidence_json,"
            "request_digest,status,revision,reason,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                CALL,
                RUN,
                TENANT,
                CASE,
                "historical-plan-reference",
                "legacy-plan-call-1",
                "response_planning",
                "block_ip",
                "1",
                "{}",
                "{}",
                "legacy only",
                "[]",
                "a" * 64,
                "proposed",
                0,
                None,
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
            ),
        )

    command.upgrade(configuration, "head")
    with sqlite3.connect(database) as connection:
        plan = connection.execute(
            "SELECT id,status,current_revision,created_by_role FROM response_plans"
        ).fetchone()
        assert plan == (CALL, "legacy_imported", 0, "legacy")
        revision = connection.execute(
            "SELECT id,reason_code,prompt_policy_version FROM response_plan_revisions"
        ).fetchone()
        assert revision == (CALL, "legacy_tool_plan", "legacy-import-v1")
        linked = connection.execute(
            "SELECT plan_id,plan_revision_id,plan_action_id FROM trusted_tool_calls"
        ).fetchone()
        assert linked == ("historical-plan-reference", CALL, None)

    command.downgrade(configuration, "20260823_04")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "response_plans" not in tables
        columns = {row[1] for row in connection.execute("PRAGMA table_info('trusted_tool_calls')")}
        assert "plan_revision_id" not in columns
        assert "plan_action_id" not in columns

    command.upgrade(configuration, "head")
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260823_06",
        )
    get_settings.cache_clear()


def test_response_plan_migration_refuses_to_drop_compiled_plans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "response-plan-downgrade-guard.db"
    configuration = _configuration(root, database, monkeypatch)
    command.upgrade(configuration, "head")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO agent_runs "
            "(id,tenant_id,principal_id,run_kind,status,goal,catalog_revision,revision,"
            "created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                RUN,
                TENANT,
                "00000000-0000-4000-8000-000000000002",
                "operations_report",
                "running",
                "compiled plan guard",
                "catalog-v1",
                0,
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO response_plans "
            "(id,tenant_id,run_id,case_id,status,current_revision,created_by_role,"
            "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                CALL,
                TENANT,
                RUN,
                None,
                "completed_advisory",
                0,
                "response_planning",
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
            ),
        )

    with pytest.raises(RuntimeError, match="compiled response plans exist"):
        command.downgrade(configuration, "20260823_04")
    get_settings.cache_clear()


def test_response_plan_migration_rejects_cross_case_historical_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "response-plan-cross-case.db"
    configuration = _configuration(root, database, monkeypatch)
    command.upgrade(configuration, "20260823_04")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO agent_runs "
            "(id,tenant_id,principal_id,run_kind,status,goal,catalog_revision,revision,"
            "created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                RUN,
                TENANT,
                "00000000-0000-4000-8000-000000000002",
                "operations_report",
                "running",
                "cross-case migration guard",
                "legacy-v1",
                0,
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
                None,
            ),
        )
        for call_id, case_id, key in (
            (CALL, CASE, "legacy-cross-case-1"),
            (SECOND_CALL, "00000000-0000-4000-8000-000000000105", "legacy-cross-case-2"),
        ):
            connection.execute(
                "INSERT INTO trusted_tool_calls "
                "(id,run_id,tenant_id,case_id,plan_id,idempotency_key,caller_role,tool_name,"
                "tool_version,arguments_json,expected_state_json,rollback_strategy,evidence_json,"
                "request_digest,status,revision,reason,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    call_id,
                    RUN,
                    TENANT,
                    case_id,
                    "historical-plan-reference",
                    key,
                    "response_planning",
                    "block_ip",
                    "1",
                    "{}",
                    "{}",
                    "legacy only",
                    "[]",
                    "a" * 64,
                    "proposed",
                    0,
                    None,
                    "2026-08-23 12:00:00",
                    "2026-08-23 12:00:00",
                ),
            )

    with pytest.raises(RuntimeError, match="cross-case historical runs"):
        command.upgrade(configuration, "head")
    get_settings.cache_clear()


def test_plan_tool_link_migration_refuses_to_drop_operator_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "response-plan-operator-audit.db"
    configuration = _configuration(root, database, monkeypatch)
    command.upgrade(configuration, "head")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO agent_runs "
            "(id,tenant_id,principal_id,run_kind,status,goal,catalog_revision,revision,"
            "created_at,updated_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                RUN,
                TENANT,
                "00000000-0000-4000-8000-000000000002",
                "operations_report",
                "running",
                "operator audit guard",
                "catalog-v1",
                0,
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO response_plans "
            "(id,tenant_id,run_id,case_id,status,current_revision,created_by_role,"
            "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                CALL,
                TENANT,
                RUN,
                None,
                "rejected",
                0,
                "response_planning",
                "2026-08-23 12:00:00",
                "2026-08-23 12:00:00",
            ),
        )
        connection.execute(
            "INSERT INTO response_plan_events "
            "(id,plan_id,tenant_id,revision,event_type,reason_code,public_summary,"
            "actor_subject_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                SECOND_CALL,
                CALL,
                TENANT,
                0,
                "plan_rejected",
                "operator_rejected",
                "Operator rejected the plan.",
                "00000000-0000-4000-8000-000000000002",
                "2026-08-23 12:00:00",
            ),
        )

    with pytest.raises(RuntimeError, match="operator response plan events exist"):
        command.downgrade(configuration, "20260823_05")
    get_settings.cache_clear()
