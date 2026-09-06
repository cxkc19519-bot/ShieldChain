from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base
from shieldchain.incidents.persistence import DEMO_TENANT_ID


class VulnerabilityFindingRow(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "scanner", "external_id", name="uq_vulnerability_finding_source"
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_vulnerability_finding_severity",
        ),
        CheckConstraint(
            "status IN ('new','triaged','remediation_approved','remediation_in_progress',"
            "'verification_pending','closed','accepted_risk')",
            name="ck_vulnerability_finding_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36), nullable=False, server_default=text(f"'{DEMO_TENANT_ID}'")
    )
    scanner: Mapped[str] = mapped_column(String(128), nullable=False)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False)
    asset_name: Mapped[str] = mapped_column(String(256), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new")
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_vulnerability_finding_tenant_status",
    VulnerabilityFindingRow.tenant_id,
    VulnerabilityFindingRow.status,
    VulnerabilityFindingRow.updated_at,
)


class VulnerabilityWorkflowEventRow(Base):
    """Append-only public audit event for one vulnerability finding."""

    __tablename__ = "vulnerability_workflow_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id"],
            ["vulnerability_findings.id"],
            name="fk_vulnerability_event_finding",
        ),
        CheckConstraint(
            "actor_type IN ('scanner','agent','human','system')",
            name="ck_vulnerability_event_actor_type",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_vulnerability_event_finding_created",
    VulnerabilityWorkflowEventRow.tenant_id,
    VulnerabilityWorkflowEventRow.finding_id,
    VulnerabilityWorkflowEventRow.created_at,
)
