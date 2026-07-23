from sqlalchemy import inspect

from shieldchain.db.base import Base


def test_trusted_tool_tables_have_tenant_foreign_keys_and_append_records() -> None:
    expected = {
        "trusted_tool_calls",
        "tool_policy_decisions",
        "tool_approvals",
        "tool_execution_attempts",
        "tool_verifications",
    }
    assert expected <= set(Base.metadata.tables)
    calls = Base.metadata.tables["trusted_tool_calls"]
    unique_names = {
        item.name for item in calls.constraints if item.__class__.__name__ == "UniqueConstraint"
    }
    assert "uq_trusted_tool_idempotency" in unique_names
    for table_name in expected - {"trusted_tool_calls"}:
        foreign_keys = inspect(Base.metadata.tables[table_name]).foreign_key_constraints
        assert any(
            {column.name for column in item.columns} == {"tool_call_id", "tenant_id"}
            for item in foreign_keys
        )
