from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base

ACTIVE_VALUES = (
    "pending",
    "collecting",
    "analyzing",
    "action_planned",
    "executing",
    "verifying",
)


class SimulationInstanceRow(Base):
    __tablename__ = "simulation_instances"
    __table_args__ = (
        UniqueConstraint("scenario_key", "generation", name="uq_simulation_scenario_generation"),
        CheckConstraint("generation >= 1", name="ck_simulation_generation_positive"),
        CheckConstraint("environment IN ('simulation')", name="ck_simulation_environment"),
        CheckConstraint(
            "connection_status IN ('active','blocked')",
            name="ck_simulation_connection_status",
        ),
        CheckConstraint(
            "firewall_status IN ('not_blocked','blocked')",
            name="ck_simulation_firewall_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario_key: Mapped[str] = mapped_column(String(64), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    connection_status: Mapped[str] = mapped_column(String(32), nullable=False)
    firewall_status: Mapped[str] = mapped_column(String(32), nullable=False)
    fail_block_consumed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IncidentRow(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("external_id", name="uq_incident_external_id"),
        UniqueConstraint("simulation_instance_id", name="uq_incident_simulation_instance"),
        CheckConstraint("remote_port BETWEEN 1 AND 65535", name="ck_incident_remote_port"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)
    simulation_instance_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("simulation_instances.id", name="fk_incident_simulation_instance"),
        nullable=False,
    )
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(128), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    remote_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    remote_port: Mapped[int] = mapped_column(Integer, nullable=False)
    process_name: Mapped[str] = mapped_column(String(128), nullable=False)
    parent_process_name: Mapped[str] = mapped_column(String(128), nullable=False)
    command_summary: Mapped[str] = mapped_column(String(512), nullable=False)
    threat_label: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class InvestigationRunRow(Base):
    __tablename__ = "investigation_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','collecting','analyzing','action_planned',"
            "'executing','verifying','needs_review','failed','interrupted','closed')",
            name="ck_investigation_run_status",
        ),
        CheckConstraint("mode IN ('normal','fail_block_once')", name="ck_investigation_run_mode"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", name="fk_investigation_run_incident"),
        nullable=False,
    )
    simulation_instance_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "simulation_instances.id",
            name="fk_investigation_run_simulation_instance",
        ),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    verification_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Index(
    "uq_active_run_per_simulation",
    InvestigationRunRow.simulation_instance_id,
    unique=True,
    sqlite_where=InvestigationRunRow.status.in_(ACTIVE_VALUES),
)


class InvestigationStepRow(Base):
    __tablename__ = "investigation_steps"
    __table_args__ = (
        UniqueConstraint("run_id", "step_key", name="uq_investigation_step_run_key"),
        CheckConstraint(
            "status IN ('pending','running','succeeded','failed','skipped')",
            name="ck_investigation_step_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_runs.id", name="fk_investigation_step_run"),
        nullable=False,
    )
    step_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    detail_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceRecordRow(Base):
    __tablename__ = "evidence_records"
    __table_args__ = (
        UniqueConstraint("run_id", "integrity_sha256", name="uq_evidence_run_integrity"),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_evidence_confidence",
        ),
        CheckConstraint("length(integrity_sha256) = 64", name="ck_evidence_sha256_length"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_runs.id", name="fk_evidence_run"),
        nullable=False,
    )
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    integrity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SimulationToolCallRow(Base):
    __tablename__ = "simulation_tool_calls"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_tool_call_idempotency_key"),
        CheckConstraint("tool_name IN ('block_ip')", name="ck_tool_call_name"),
        CheckConstraint(
            "status IN ('blocked','already_blocked','failed')",
            name="ck_tool_call_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_runs.id", name="fk_tool_call_run"),
        nullable=False,
    )
    simulation_instance_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("simulation_instances.id", name="fk_tool_call_simulation_instance"),
        nullable=False,
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    before_state_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    after_state_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("incident_id", "sequence", name="uq_audit_incident_sequence"),
        CheckConstraint("sequence >= 1", name="ck_audit_sequence_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", name="fk_audit_incident"),
        nullable=False,
    )
    run_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("investigation_runs.id", name="fk_audit_run"),
        nullable=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
