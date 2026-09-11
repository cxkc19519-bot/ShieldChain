from collections.abc import Sequence

from sqlalchemy.engine import Connection

from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url


def _plan(connection: Connection, sql: str, parameters: Sequence[str]) -> str:
    rows = connection.exec_driver_sql(
        f"EXPLAIN QUERY PLAN {sql}", tuple(parameters)
    ).all()
    return " | ".join(str(row[-1]) for row in rows)


def test_incident_run_lists_use_covering_filter_and_order_indexes() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        incident = _plan(
            connection,
            "SELECT id FROM investigation_runs "
            "WHERE incident_id = ? ORDER BY created_at, id",
            ("incident",),
        )
        simulation = _plan(
            connection,
            "SELECT id FROM investigation_runs "
            "WHERE simulation_instance_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
            ("simulation",),
        )
    engine.dispose()
    assert "ix_investigation_run_incident_created" in incident
    assert "ix_investigation_run_simulation_created" in simulation
    assert "USE TEMP B-TREE" not in incident
    assert "USE TEMP B-TREE" not in simulation


def test_trusted_tool_trace_uses_tenant_run_order_index() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        plan = _plan(
            connection,
            "SELECT id FROM trusted_tool_calls "
            "WHERE tenant_id = ? AND run_id = ? ORDER BY created_at, id",
            ("tenant", "run"),
        )
    engine.dispose()
    assert "ix_trusted_tool_call_tenant_run_created" in plan
    assert "USE TEMP B-TREE" not in plan


def test_model_metadata_contains_only_the_phase8_replacement_tool_index() -> None:
    incident_indexes = {item.name for item in Base.metadata.tables["investigation_runs"].indexes}
    tool_indexes = {item.name for item in Base.metadata.tables["trusted_tool_calls"].indexes}
    assert {
        "ix_investigation_run_incident_created",
        "ix_investigation_run_simulation_created",
    }.issubset(incident_indexes)
    assert "ix_trusted_tool_call_tenant_run_created" in tool_indexes
    assert "ix_trusted_tool_call_tenant_run" not in tool_indexes
