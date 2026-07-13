"""phase 2 incident loop

Revision ID: 20260713_01
Revises:
Create Date: 2026-07-14 00:24:11.455385
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260713_01"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "simulation_instances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scenario_key", sa.String(length=64), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("connection_status", sa.String(length=32), nullable=False),
        sa.Column("firewall_status", sa.String(length=32), nullable=False),
        sa.Column("fail_block_consumed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "connection_status IN ('active','blocked')", name="ck_simulation_connection_status"
        ),
        sa.CheckConstraint("environment IN ('simulation')", name="ck_simulation_environment"),
        sa.CheckConstraint(
            "firewall_status IN ('not_blocked','blocked')", name="ck_simulation_firewall_status"
        ),
        sa.CheckConstraint("generation >= 1", name="ck_simulation_generation_positive"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scenario_key", "generation", name="uq_simulation_scenario_generation"),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=False),
        sa.Column("simulation_instance_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("endpoint", sa.String(length=128), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("remote_ip", sa.String(length=45), nullable=False),
        sa.Column("remote_port", sa.Integer(), nullable=False),
        sa.Column("process_name", sa.String(length=128), nullable=False),
        sa.Column("parent_process_name", sa.String(length=128), nullable=False),
        sa.Column("command_summary", sa.String(length=512), nullable=False),
        sa.Column("threat_label", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("remote_port BETWEEN 1 AND 65535", name="ck_incident_remote_port"),
        sa.ForeignKeyConstraint(
            ["simulation_instance_id"],
            ["simulation_instances.id"],
            name="fk_incident_simulation_instance",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("simulation_instance_id", name="uq_incident_simulation_instance"),
    )
    op.create_table(
        "investigation_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("simulation_instance_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("assessment_json", sa.JSON(), nullable=True),
        sa.Column("verification_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "mode IN ('normal','fail_block_once')", name="ck_investigation_run_mode"
        ),
        sa.CheckConstraint(
            "status IN ('pending','collecting','analyzing','action_planned',"
            "'executing','verifying','needs_review','failed','interrupted','closed')",
            name="ck_investigation_run_status",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name="fk_investigation_run_incident"
        ),
        sa.ForeignKeyConstraint(
            ["simulation_instance_id"],
            ["simulation_instances.id"],
            name="fk_investigation_run_simulation_instance",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_active_run_per_simulation",
        "investigation_runs",
        ["simulation_instance_id"],
        unique=True,
        sqlite_where=sa.text(
            "status IN ('pending', 'collecting', 'analyzing', 'action_planned', "
            "'executing', 'verifying')"
        ),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.CheckConstraint("sequence >= 1", name="ck_audit_sequence_positive"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], name="fk_audit_incident"),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"], name="fk_audit_run"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "sequence", name="uq_audit_incident_sequence"),
    )
    op.create_table(
        "evidence_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column("raw_reference", sa.String(length=512), nullable=False),
        sa.Column("integrity_sha256", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_evidence_confidence"
        ),
        sa.CheckConstraint("length(integrity_sha256) = 64", name="ck_evidence_sha256_length"),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"], name="fk_evidence_run"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "integrity_sha256", name="uq_evidence_run_integrity"),
    )
    op.create_table(
        "investigation_steps",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("step_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("detail_json", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','running','succeeded','failed','skipped')",
            name="ck_investigation_step_status",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["investigation_runs.id"], name="fk_investigation_step_run"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "step_key", name="uq_investigation_step_run_key"),
    )
    op.create_table(
        "simulation_tool_calls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("simulation_instance_id", sa.String(length=36), nullable=False),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("before_state_json", sa.JSON(), nullable=False),
        sa.Column("after_state_json", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('blocked','already_blocked','failed')", name="ck_tool_call_status"
        ),
        sa.CheckConstraint("tool_name IN ('block_ip')", name="ck_tool_call_name"),
        sa.ForeignKeyConstraint(["run_id"], ["investigation_runs.id"], name="fk_tool_call_run"),
        sa.ForeignKeyConstraint(
            ["simulation_instance_id"],
            ["simulation_instances.id"],
            name="fk_tool_call_simulation_instance",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_tool_call_idempotency_key"),
    )


def downgrade() -> None:
    op.drop_table("simulation_tool_calls")
    op.drop_table("investigation_steps")
    op.drop_table("evidence_records")
    op.drop_table("audit_events")
    op.drop_table("investigation_runs")
    op.drop_table("incidents")
    op.drop_table("simulation_instances")
