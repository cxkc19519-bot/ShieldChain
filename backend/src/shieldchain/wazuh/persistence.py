from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base
from shieldchain.incidents.persistence import DEMO_TENANT_ID


class WazuhAlertRow(Base):
    __tablename__ = "wazuh_alerts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "external_id", name="uq_wazuh_alert_tenant_external"),
        CheckConstraint("severity BETWEEN 0 AND 15", name="ck_wazuh_alert_severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36), nullable=False, server_default=text(f"'{DEMO_TENANT_ID}'")
    )
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    mitre_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    process_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    parent_process_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_wazuh_alert_tenant_received",
    WazuhAlertRow.tenant_id,
    WazuhAlertRow.received_at,
    WazuhAlertRow.id,
)


class WazuhReviewCaseRow(Base):
    """Review-only ShieldChain case derived from one high-risk Wazuh alert."""

    __tablename__ = "wazuh_review_cases"
    __table_args__ = (
        UniqueConstraint("tenant_id", "alert_id", name="uq_wazuh_review_case_tenant_alert"),
        UniqueConstraint(
            "tenant_id",
            "tracking_year",
            "tracking_sequence",
            name="uq_wazuh_review_case_tenant_tracking",
        ),
        CheckConstraint("status = 'needs_review'", name="ck_wazuh_review_case_status"),
        CheckConstraint("severity BETWEEN 0 AND 15", name="ck_wazuh_review_case_severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36), nullable=False, server_default=text(f"'{DEMO_TENANT_ID}'")
    )
    alert_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tracking_year: Mapped[int] = mapped_column(Integer, nullable=False)
    tracking_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="needs_review")
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_wazuh_review_case_tenant_updated",
    WazuhReviewCaseRow.tenant_id,
    WazuhReviewCaseRow.updated_at,
    WazuhReviewCaseRow.id,
)


class WazuhCaseEvidenceRow(Base):
    """Confirmed evidence copied from a normalized Wazuh alert for one agent run."""

    __tablename__ = "wazuh_case_evidence"
    __table_args__ = (
        UniqueConstraint("run_id", "integrity_sha256", name="uq_wazuh_evidence_run_integrity"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_wazuh_evidence_run_tenant",
        ),
        CheckConstraint("confirmed = 1", name="ck_wazuh_evidence_confirmed"),
        CheckConstraint("length(integrity_sha256) = 64", name="ck_wazuh_evidence_sha256_length"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    integrity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_wazuh_evidence_run_observed",
    WazuhCaseEvidenceRow.run_id,
    WazuhCaseEvidenceRow.observed_at,
)


class WazuhCaseRunRow(Base):
    """Explicit tenant-bound link between one live review case and one agent run."""

    __tablename__ = "wazuh_case_runs"
    __table_args__ = (
        UniqueConstraint("run_id", "tenant_id", name="uq_wazuh_case_run_tenant"),
        UniqueConstraint("case_id", "tenant_id", name="uq_wazuh_case_single_run"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_wazuh_case_run_agent_tenant",
        ),
    )

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WazuhCaseAuditRow(Base):
    """Append-only public audit trail for a live Wazuh case run."""

    __tablename__ = "wazuh_case_audit_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["wazuh_case_runs.run_id", "wazuh_case_runs.tenant_id"],
            name="fk_wazuh_audit_run_tenant",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


Index(
    "ix_wazuh_case_audit_run_time",
    WazuhCaseAuditRow.run_id,
    WazuhCaseAuditRow.occurred_at,
    WazuhCaseAuditRow.id,
)
