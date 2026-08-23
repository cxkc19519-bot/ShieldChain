from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base


class OperationsRunRow(Base):
    __tablename__ = "operations_runs"
    __table_args__ = (
        UniqueConstraint("run_id", "tenant_id", name="uq_operations_run_id_tenant"),
        UniqueConstraint("report_id", name="uq_operations_run_report"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_operations_run_agent_tenant",
        ),
        CheckConstraint("end_at >= start_at", name="ck_operations_run_time_window"),
    )

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_operations_run_tenant_created",
    OperationsRunRow.tenant_id,
    OperationsRunRow.created_at,
    OperationsRunRow.run_id,
)
