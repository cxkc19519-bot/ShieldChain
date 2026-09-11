from sqlalchemy import JSON, DateTime, ForeignKeyConstraint, UniqueConstraint

from shieldchain.agents.persistence import (
    AgentExecutionRow,
    AgentHandoffRow,
    AgentPrivateContextRow,
    CaseContextRow,
    ConfirmedCaseFactRow,
)
from shieldchain.db.base import Base

TABLES = {
    "case_contexts",
    "confirmed_case_facts",
    "agent_private_contexts",
    "agent_handoffs",
    "agent_executions",
}


def test_agent_context_tables_are_registered_with_tenant_boundaries() -> None:
    assert TABLES <= Base.metadata.tables.keys()
    for name in TABLES:
        table = Base.metadata.tables[name]
        assert table.c.tenant_id.nullable is False
        assert table.c.tenant_id.type.length == 36
        tenant_fks = [
            constraint
            for constraint in table.constraints
            if isinstance(constraint, ForeignKeyConstraint)
            and "tenant_id" in constraint.column_keys
        ]
        assert len(tenant_fks) == 1
        assert tenant_fks[0].ondelete is None


def test_mutable_context_rows_have_revision_and_append_only_rows_do_not() -> None:
    assert CaseContextRow.revision.nullable is False
    assert AgentPrivateContextRow.revision.nullable is False
    for row_type in (ConfirmedCaseFactRow, AgentHandoffRow, AgentExecutionRow):
        assert "revision" not in row_type.__table__.c
        assert "updated_at" not in row_type.__table__.c


def test_run_and_role_uniqueness_contracts() -> None:
    case_unique = {
        constraint.name
        for constraint in CaseContextRow.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    private_unique = {
        constraint.name
        for constraint in AgentPrivateContextRow.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert "uq_case_context_run" in case_unique
    assert "uq_private_context_run_role" in private_unique


def test_json_and_utc_storage_contracts() -> None:
    assert isinstance(CaseContextRow.budget_json.type, JSON)
    assert isinstance(ConfirmedCaseFactRow.references_json.type, JSON)
    assert isinstance(AgentPrivateContextRow.working_items_json.type, JSON)
    assert isinstance(AgentHandoffRow.open_questions_json.type, JSON)
    assert isinstance(AgentExecutionRow.hypotheses_json.type, JSON)
    for table_name in TABLES:
        for column in Base.metadata.tables[table_name].columns:
            if isinstance(column.type, DateTime):
                assert column.type.timezone is True
                assert column.nullable is False
