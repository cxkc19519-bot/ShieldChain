import json
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from shieldchain.core.config import get_settings

TENANT = "00000000-0000-4000-8000-000000000001"
RUN = "00000000-0000-4000-8000-000000000401"
LOOP = "00000000-0000-4000-8000-000000000402"
OBSERVATION = "00000000-0000-4000-8000-000000000403"
ASSESSMENT = "00000000-0000-4000-8000-000000000404"
PLAN_REVISION = "00000000-0000-4000-8000-000000000406"


def _configuration(root: Path, database: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
    get_settings.cache_clear()
    return Config(str(root / "backend" / "alembic.ini"))


def test_react_completion_migration_round_trips_and_protects_new_categories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "react-completion-migration.db"
    configuration = _configuration(root, database, monkeypatch)
    command.upgrade(configuration, "20260823_06")
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
                "react migration guard",
                "catalog-v1",
                0,
                "2026-08-24 00:00:00",
                "2026-08-24 00:00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO react_loops "
            "(id,tenant_id,case_id,run_id,status,revision,budget_json,"
            "observation_fingerprints_json,started_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                LOOP,
                TENANT,
                "00000000-0000-4000-8000-000000000405",
                RUN,
                "completed",
                1,
                json.dumps(
                    {
                        "step_limit": 2,
                        "steps_used": 1,
                        "loop_limit": 2,
                        "loops_used": 1,
                        "time_limit_seconds": 60,
                        "time_used_seconds": 1,
                        "token_limit": 100,
                        "tokens_used": 0,
                        "cost_limit_usd": 1,
                        "cost_used_usd": 0,
                        "tool_call_limit": 2,
                        "tool_calls_used": 1,
                    }
                ),
                "[]",
                "2026-08-24 00:00:00",
                "2026-08-24 00:00:00",
            ),
        )
        connection.execute(
            "INSERT INTO react_observations "
            "(id,loop_id,tenant_id,case_id,run_id,iteration,source,status,reason_code,"
            "references_json,tool_call_id,verification_id,observed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                OBSERVATION,
                LOOP,
                TENANT,
                "00000000-0000-4000-8000-000000000405",
                RUN,
                1,
                "evidence",
                "completed",
                "verification_verified",
                "[]",
                None,
                None,
                "2026-08-24 00:00:00",
            ),
        )
        connection.execute(
            "INSERT INTO react_assessments "
            "(id,observation_id,tenant_id,category,recoverable,confidence,reason_code,"
            "assessed_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                ASSESSMENT,
                OBSERVATION,
                TENANT,
                "completed",
                0,
                1.0,
                "classified_completed",
                "2026-08-24 00:00:00",
            ),
        )
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "20260824_08",
        )

    with pytest.raises(RuntimeError, match="extended ReAct records exist"):
        command.downgrade(configuration, "20260823_06")
    get_settings.cache_clear()


def test_approval_expired_category_blocks_unsafe_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[4]
    database = tmp_path / "react-approval-expired-migration.db"
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
                "needs_review",
                "approval expiry migration guard",
                "catalog-v1",
                0,
                "2026-08-24 00:00:00",
                "2026-08-24 00:00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO react_loops "
            "(id,tenant_id,case_id,run_id,status,revision,budget_json,"
            "observation_fingerprints_json,started_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                LOOP,
                TENANT,
                "00000000-0000-4000-8000-000000000405",
                RUN,
                "awaiting_human",
                1,
                json.dumps(
                    {
                        "step_limit": 2,
                        "steps_used": 1,
                        "loop_limit": 2,
                        "loops_used": 1,
                        "time_limit_seconds": 60,
                        "time_used_seconds": 1,
                        "token_limit": 100,
                        "tokens_used": 0,
                        "cost_limit_usd": 1,
                        "cost_used_usd": 0,
                        "tool_call_limit": 2,
                        "tool_calls_used": 1,
                    }
                ),
                "[]",
                "2026-08-24 00:00:00",
                "2026-08-24 00:00:00",
            ),
        )
        connection.execute(
            "INSERT INTO react_plan_revisions "
            "(id,loop_id,tenant_id,case_id,run_id,revision,parent_revision,"
            "retained_action_ids_json,removed_action_ids_json,added_actions_json,reason,"
            "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                PLAN_REVISION,
                LOOP,
                TENANT,
                "00000000-0000-4000-8000-000000000405",
                RUN,
                1,
                0,
                "[]",
                "[]",
                "[]",
                "approval_expired",
                "2026-08-24 00:00:00",
            ),
        )

    with pytest.raises(RuntimeError, match="approval-expired ReAct records exist"):
        command.downgrade(configuration, "20260824_07")
    get_settings.cache_clear()
