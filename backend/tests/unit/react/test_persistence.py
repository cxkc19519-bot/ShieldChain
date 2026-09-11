from sqlalchemy import inspect

from shieldchain.db.base import Base


def test_react_tables_have_tenant_bound_foreign_keys_and_constraints() -> None:
    expected = {
        "react_loops",
        "react_observations",
        "react_assessments",
        "react_control_events",
        "react_plan_revisions",
        "react_decisions",
    }
    assert expected <= set(Base.metadata.tables)
    for name in expected - {"react_loops"}:
        foreign_keys = inspect(Base.metadata.tables[name]).foreign_key_constraints
        assert any("tenant_id" in {column.name for column in item.columns} for item in foreign_keys)
    loops = Base.metadata.tables["react_loops"]
    assert any(
        item.name == "fk_react_loop_run_tenant" for item in inspect(loops).foreign_key_constraints
    )
    plans = Base.metadata.tables["react_plan_revisions"]
    assert any(item.name == "uq_react_plan_revision_number" for item in plans.constraints)
