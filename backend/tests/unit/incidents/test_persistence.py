from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    UniqueConstraint,
    create_engine,
    insert,
)
from sqlalchemy.dialects import sqlite
from sqlalchemy.exc import IntegrityError

from shieldchain.db.base import Base

PHASE_TWO_TABLES = {
    "simulation_instances",
    "incidents",
    "investigation_runs",
    "investigation_steps",
    "evidence_records",
    "simulation_tool_calls",
    "audit_events",
}

EXPECTED_COLUMNS = {
    "simulation_instances": {
        "id",
        "scenario_key",
        "generation",
        "environment",
        "connection_status",
        "firewall_status",
        "fail_block_consumed",
        "created_at",
        "updated_at",
    },
    "incidents": {
        "id",
        "external_id",
        "simulation_instance_id",
        "alert_id",
        "endpoint",
        "username",
        "source_ip",
        "remote_ip",
        "remote_port",
        "process_name",
        "parent_process_name",
        "command_summary",
        "threat_label",
        "created_at",
    },
    "investigation_runs": {
        "id",
        "incident_id",
        "simulation_instance_id",
        "status",
        "mode",
        "assessment_json",
        "verification_json",
        "created_at",
        "updated_at",
        "completed_at",
    },
    "investigation_steps": {
        "id",
        "run_id",
        "step_key",
        "status",
        "detail_json",
        "error_code",
        "started_at",
        "completed_at",
    },
    "evidence_records": {
        "id",
        "run_id",
        "evidence_type",
        "source",
        "observed_at",
        "summary",
        "raw_reference",
        "integrity_sha256",
        "confidence",
        "confirmed",
        "payload_json",
        "created_at",
    },
    "simulation_tool_calls": {
        "id",
        "run_id",
        "simulation_instance_id",
        "tool_name",
        "target",
        "idempotency_key",
        "status",
        "before_state_json",
        "after_state_json",
        "error_code",
        "requested_at",
        "completed_at",
    },
    "audit_events": {
        "id",
        "incident_id",
        "run_id",
        "sequence",
        "event_type",
        "request_id",
        "occurred_at",
        "payload_json",
    },
}


def _named_constraints(table_name: str, constraint_type: type) -> set[str | None]:
    return {
        constraint.name
        for constraint in Base.metadata.tables[table_name].constraints
        if isinstance(constraint, constraint_type)
    }


def test_phase_two_tables_and_exact_columns_are_registered() -> None:
    assert PHASE_TWO_TABLES.issubset(Base.metadata.tables)
    for table_name, columns in EXPECTED_COLUMNS.items():
        assert set(Base.metadata.tables[table_name].columns.keys()) == columns


def test_named_unique_and_check_constraints_exist() -> None:
    expected_unique = {
        "simulation_instances": {"uq_simulation_scenario_generation"},
        "incidents": {"uq_incident_simulation_instance"},
        "investigation_steps": {"uq_investigation_step_run_key"},
        "evidence_records": {"uq_evidence_run_integrity"},
        "simulation_tool_calls": {"uq_tool_call_idempotency_key"},
        "audit_events": {"uq_audit_incident_sequence"},
    }
    expected_checks = {
        "simulation_instances": {
            "ck_simulation_generation_positive",
            "ck_simulation_environment",
            "ck_simulation_connection_status",
            "ck_simulation_firewall_status",
        },
        "incidents": {"ck_incident_remote_port"},
        "investigation_runs": {
            "ck_investigation_run_status",
            "ck_investigation_run_mode",
        },
        "investigation_steps": {"ck_investigation_step_status"},
        "evidence_records": {
            "ck_evidence_confidence",
            "ck_evidence_sha256_length",
        },
        "simulation_tool_calls": {"ck_tool_call_name", "ck_tool_call_status"},
        "audit_events": {"ck_audit_sequence_positive"},
    }

    for table_name, names in expected_unique.items():
        assert names == _named_constraints(table_name, UniqueConstraint)
    for table_name, names in expected_checks.items():
        assert names <= _named_constraints(table_name, CheckConstraint)


def test_foreign_keys_have_exact_targets_and_are_not_cascading() -> None:
    expected = {
        ("incidents", "simulation_instance_id"): (
            "simulation_instances.id",
            "fk_incident_simulation_instance",
        ),
        ("investigation_runs", "incident_id"): (
            "incidents.id",
            "fk_investigation_run_incident",
        ),
        ("investigation_runs", "simulation_instance_id"): (
            "simulation_instances.id",
            "fk_investigation_run_simulation_instance",
        ),
        ("investigation_steps", "run_id"): (
            "investigation_runs.id",
            "fk_investigation_step_run",
        ),
        ("evidence_records", "run_id"): (
            "investigation_runs.id",
            "fk_evidence_run",
        ),
        ("simulation_tool_calls", "run_id"): (
            "investigation_runs.id",
            "fk_tool_call_run",
        ),
        ("simulation_tool_calls", "simulation_instance_id"): (
            "simulation_instances.id",
            "fk_tool_call_simulation_instance",
        ),
        ("audit_events", "incident_id"): (
            "incidents.id",
            "fk_audit_incident",
        ),
        ("audit_events", "run_id"): ("investigation_runs.id", "fk_audit_run"),
    }

    actual: dict[tuple[str, str], tuple[str, str | None]] = {}
    for table_name in PHASE_TWO_TABLES:
        table = Base.metadata.tables[table_name]
        for constraint in table.constraints:
            if isinstance(constraint, ForeignKeyConstraint):
                assert constraint.ondelete is None
                for element in constraint.elements:
                    actual[(table_name, element.parent.name)] = (
                        element.target_fullname,
                        constraint.name,
                    )
    assert actual == expected


def test_uuid_json_and_timestamp_column_contracts() -> None:
    uuid_columns = {
        ("simulation_instances", "id"),
        ("incidents", "id"),
        ("incidents", "simulation_instance_id"),
        ("investigation_runs", "id"),
        ("investigation_runs", "incident_id"),
        ("investigation_runs", "simulation_instance_id"),
        ("investigation_steps", "id"),
        ("investigation_steps", "run_id"),
        ("evidence_records", "id"),
        ("evidence_records", "run_id"),
        ("simulation_tool_calls", "id"),
        ("simulation_tool_calls", "run_id"),
        ("simulation_tool_calls", "simulation_instance_id"),
        ("audit_events", "id"),
        ("audit_events", "incident_id"),
        ("audit_events", "run_id"),
    }
    nullable_columns = {
        ("investigation_runs", "assessment_json"),
        ("investigation_runs", "verification_json"),
        ("investigation_runs", "completed_at"),
        ("investigation_steps", "error_code"),
        ("investigation_steps", "completed_at"),
        ("simulation_tool_calls", "error_code"),
        ("audit_events", "run_id"),
    }
    json_columns = {
        ("investigation_runs", "assessment_json"),
        ("investigation_runs", "verification_json"),
        ("investigation_steps", "detail_json"),
        ("evidence_records", "payload_json"),
        ("simulation_tool_calls", "before_state_json"),
        ("simulation_tool_calls", "after_state_json"),
        ("audit_events", "payload_json"),
    }

    for table_name, column_name in uuid_columns:
        column = Base.metadata.tables[table_name].c[column_name]
        assert column.type.length == 36
    for table_name, column_name in json_columns:
        assert isinstance(Base.metadata.tables[table_name].c[column_name].type, JSON)
    for table_name in PHASE_TWO_TABLES:
        for column in Base.metadata.tables[table_name].columns:
            if isinstance(column.type, DateTime):
                assert column.type.timezone is True
                assert column.nullable is ((table_name, column.name) in nullable_columns)
            elif not column.primary_key:
                assert column.nullable is ((table_name, column.name) in nullable_columns)


def test_active_run_partial_unique_sqlite_index_has_exact_predicate() -> None:
    table = Base.metadata.tables["investigation_runs"]
    index = next(index for index in table.indexes if index.name == "uq_active_run_per_simulation")
    assert index.unique is True
    assert [column.name for column in index.columns] == ["simulation_instance_id"]
    predicate = index.dialect_options["sqlite"]["where"]
    compiled = str(
        predicate.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True})
    )
    assert compiled == (
        "investigation_runs.status IN ('pending', 'collecting', 'analyzing', "
        "'action_planned', 'executing', 'verifying')"
    )


def test_sqlite_rejects_a_second_active_run_for_one_simulation() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    simulation = Base.metadata.tables["simulation_instances"]
    incident = Base.metadata.tables["incidents"]
    run = Base.metadata.tables["investigation_runs"]
    simulation_id = "00000000-0000-0000-0000-000000000001"
    incident_id = "00000000-0000-0000-0000-000000000002"
    with engine.begin() as connection:
        connection.execute(
            insert(simulation),
            {
                "id": simulation_id,
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
            insert(incident),
            {
                "id": incident_id,
                "external_id": "INC-1",
                "simulation_instance_id": simulation_id,
                "alert_id": "ALT-1",
                "endpoint": "workstation-1",
                "username": "analyst",
                "source_ip": "10.0.0.1",
                "remote_ip": "203.0.113.1",
                "remote_port": 443,
                "process_name": "powershell.exe",
                "parent_process_name": "outlook.exe",
                "command_summary": "download payload",
                "threat_label": "phishing",
                "created_at": now,
            },
        )
        connection.execute(
            insert(run),
            {
                "id": "00000000-0000-0000-0000-000000000003",
                "incident_id": incident_id,
                "simulation_instance_id": simulation_id,
                "status": "pending",
                "mode": "normal",
                "created_at": now,
                "updated_at": now,
            },
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                insert(run),
                {
                    "id": "00000000-0000-0000-0000-000000000004",
                    "incident_id": incident_id,
                    "simulation_instance_id": simulation_id,
                    "status": "collecting",
                    "mode": "normal",
                    "created_at": now,
                    "updated_at": now,
                },
            )


def test_sqlite_allows_one_external_id_across_different_simulations() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    simulation = Base.metadata.tables["simulation_instances"]
    incident = Base.metadata.tables["incidents"]

    with engine.begin() as connection:
        connection.execute(
            insert(simulation),
            [
                {
                    "id": "00000000-0000-0000-0000-000000000011",
                    "scenario_key": "phishing",
                    "generation": 1,
                    "environment": "simulation",
                    "connection_status": "active",
                    "firewall_status": "not_blocked",
                    "fail_block_consumed": False,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": "00000000-0000-0000-0000-000000000012",
                    "scenario_key": "phishing",
                    "generation": 2,
                    "environment": "simulation",
                    "connection_status": "active",
                    "firewall_status": "not_blocked",
                    "fail_block_consumed": False,
                    "created_at": now,
                    "updated_at": now,
                },
            ],
        )
        connection.execute(
            insert(incident),
            [
                {
                    "id": "00000000-0000-0000-0000-000000000013",
                    "external_id": "INC-2026-0001",
                    "simulation_instance_id": "00000000-0000-0000-0000-000000000011",
                    "alert_id": "ALT-1",
                    "endpoint": "workstation-1",
                    "username": "analyst",
                    "source_ip": "10.0.0.1",
                    "remote_ip": "203.0.113.1",
                    "remote_port": 443,
                    "process_name": "powershell.exe",
                    "parent_process_name": "outlook.exe",
                    "command_summary": "download payload",
                    "threat_label": "phishing",
                    "created_at": now,
                },
                {
                    "id": "00000000-0000-0000-0000-000000000014",
                    "external_id": "INC-2026-0001",
                    "simulation_instance_id": "00000000-0000-0000-0000-000000000012",
                    "alert_id": "ALT-1",
                    "endpoint": "workstation-1",
                    "username": "analyst",
                    "source_ip": "10.0.0.1",
                    "remote_ip": "203.0.113.1",
                    "remote_port": 443,
                    "process_name": "powershell.exe",
                    "parent_process_name": "outlook.exe",
                    "command_summary": "download payload",
                    "threat_label": "phishing",
                    "created_at": now,
                },
            ],
        )


def test_sqlite_rejects_two_incidents_for_one_simulation() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    simulation = Base.metadata.tables["simulation_instances"]
    incident = Base.metadata.tables["incidents"]
    simulation_id = "00000000-0000-0000-0000-000000000021"

    with engine.begin() as connection:
        connection.execute(
            insert(simulation),
            {
                "id": simulation_id,
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
            insert(incident),
            {
                "id": "00000000-0000-0000-0000-000000000022",
                "external_id": "INC-2026-0001",
                "simulation_instance_id": simulation_id,
                "alert_id": "ALT-1",
                "endpoint": "workstation-1",
                "username": "analyst",
                "source_ip": "10.0.0.1",
                "remote_ip": "203.0.113.1",
                "remote_port": 443,
                "process_name": "powershell.exe",
                "parent_process_name": "outlook.exe",
                "command_summary": "download payload",
                "threat_label": "phishing",
                "created_at": now,
            },
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                insert(incident),
                {
                    "id": "00000000-0000-0000-0000-000000000023",
                    "external_id": "INC-2026-0002",
                    "simulation_instance_id": simulation_id,
                    "alert_id": "ALT-2",
                    "endpoint": "workstation-1",
                    "username": "analyst",
                    "source_ip": "10.0.0.1",
                    "remote_ip": "203.0.113.2",
                    "remote_port": 443,
                    "process_name": "powershell.exe",
                    "parent_process_name": "outlook.exe",
                    "command_summary": "download another payload",
                    "threat_label": "phishing",
                    "created_at": now,
                },
            )


def test_migration_upgrade_and_downgrade_round_trip(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    database_path = tmp_path / "migration-round-trip.db"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
    command = [
        sys.executable,
        "-m",
        "alembic",
        "-c",
        str(repository_root / "backend" / "alembic.ini"),
    ]

    subprocess.run(
        [*command, "upgrade", "head"],
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(database_path) as connection:
        upgraded_tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert PHASE_TWO_TABLES <= upgraded_tables

    subprocess.run(
        [*command, "downgrade", "-1"],
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(database_path) as connection:
        downgraded_tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert PHASE_TWO_TABLES.isdisjoint(downgraded_tables)
