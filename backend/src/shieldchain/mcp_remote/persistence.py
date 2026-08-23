from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    select,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from shieldchain.db.base import Base


class McpPeerSnapshotRow(Base):
    __tablename__ = "mcp_peer_snapshots"
    __table_args__ = (
        CheckConstraint("status IN ('accepted','rejected')", name="ck_mcp_peer_snapshot_status"),
        CheckConstraint(
            "(status = 'accepted' AND error_code IS NULL) OR "
            "(status = 'rejected' AND error_code IS NOT NULL)",
            name="ck_mcp_peer_snapshot_error",
        ),
        CheckConstraint("expires_at >= discovered_at", name="ck_mcp_peer_snapshot_expiry"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    peer_id: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    transport: Mapped[str] = mapped_column(String(32), nullable=False)
    network_policy: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    catalog_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_mcp_peer_snapshot_peer_discovered",
    McpPeerSnapshotRow.peer_id,
    McpPeerSnapshotRow.discovered_at,
    McpPeerSnapshotRow.id,
)


class McpToolSnapshotRow(Base):
    __tablename__ = "mcp_tool_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "peer_snapshot_id", "remote_name", name="uq_mcp_tool_snapshot_remote_name"
        ),
        UniqueConstraint("peer_snapshot_id", "alias", name="uq_mcp_tool_snapshot_alias"),
        CheckConstraint("classification = 'read_only'", name="ck_mcp_tool_snapshot_read_only"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    peer_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("mcp_peer_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool_identity: Mapped[str] = mapped_column(String(36), nullable=False)
    remote_name: Mapped[str] = mapped_column(String(128), nullable=False)
    alias: Mapped[str] = mapped_column(String(128), nullable=False)
    label: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(String(4096), nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    allowed_roles_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    input_schema_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    output_schema_json: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    remote_annotations_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    schema_revision: Mapped[str] = mapped_column(String(64), nullable=False)


Index("ix_mcp_tool_snapshot_alias", McpToolSnapshotRow.alias)


class AgentRunMcpSnapshotRow(Base):
    __tablename__ = "agent_run_mcp_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_agent_run_mcp_snapshot_run_tenant",
        ),
        UniqueConstraint("run_id", "peer_id", name="uq_agent_run_mcp_snapshot_peer"),
    )

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    peer_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    peer_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("mcp_peer_snapshots.id"),
        nullable=False,
    )
    catalog_revision: Mapped[str] = mapped_column(String(64), nullable=False)


Index(
    "ix_agent_run_mcp_snapshot_peer",
    AgentRunMcpSnapshotRow.peer_id,
    AgentRunMcpSnapshotRow.peer_snapshot_id,
)


@dataclass(frozen=True, slots=True)
class McpToolSnapshot:
    tool_identity: UUID
    remote_name: str
    alias: str
    label: str
    description: str
    classification: str
    allowed_roles: tuple[str, ...]
    input_schema: dict[str, object]
    output_schema: dict[str, object] | None
    remote_annotations: dict[str, object]
    schema_revision: str


@dataclass(frozen=True, slots=True)
class McpPeerSnapshot:
    id: UUID
    peer_id: str
    endpoint: str
    protocol_version: str
    catalog_revision: str
    discovered_at: datetime
    expires_at: datetime
    tools: tuple[McpToolSnapshot, ...]


class McpSnapshotStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def latest_accepted(self, peer_id: str) -> McpPeerSnapshot | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(McpPeerSnapshotRow)
                .where(
                    McpPeerSnapshotRow.peer_id == peer_id,
                    McpPeerSnapshotRow.status == "accepted",
                )
                .order_by(McpPeerSnapshotRow.discovered_at.desc(), McpPeerSnapshotRow.id.desc())
                .limit(1)
            )
            return self._to_snapshot(session, row) if row is not None else None

    def latest_usable(self, peer_id: str, *, now: datetime) -> McpPeerSnapshot | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(McpPeerSnapshotRow)
                .where(
                    McpPeerSnapshotRow.peer_id == peer_id,
                )
                .order_by(McpPeerSnapshotRow.discovered_at.desc(), McpPeerSnapshotRow.id.desc())
                .limit(1)
            )
            if row is None or row.status != "accepted" or _utc(row.expires_at) <= _utc(now):
                return None
            return self._to_snapshot(session, row)

    def save_accepted(
        self,
        *,
        peer_id: str,
        endpoint: str,
        network_policy: str,
        protocol_version: str,
        catalog_revision: str,
        discovered_at: datetime,
        expires_at: datetime,
        tools: tuple[McpToolSnapshot, ...],
    ) -> UUID:
        snapshot_id = uuid4()
        with self._session_factory.begin() as session:
            session.add(
                McpPeerSnapshotRow(
                    id=str(snapshot_id),
                    peer_id=peer_id,
                    endpoint=endpoint,
                    transport="streamable_http",
                    network_policy=network_policy,
                    protocol_version=protocol_version,
                    catalog_revision=catalog_revision,
                    status="accepted",
                    error_code=None,
                    discovered_at=discovered_at,
                    expires_at=expires_at,
                )
            )
            session.add_all(
                McpToolSnapshotRow(
                    id=str(uuid4()),
                    peer_snapshot_id=str(snapshot_id),
                    tool_identity=str(tool.tool_identity),
                    remote_name=tool.remote_name,
                    alias=tool.alias,
                    label=tool.label,
                    description=tool.description,
                    classification=tool.classification,
                    allowed_roles_json=list(tool.allowed_roles),
                    input_schema_json=tool.input_schema,
                    output_schema_json=tool.output_schema,
                    remote_annotations_json=tool.remote_annotations,
                    schema_revision=tool.schema_revision,
                )
                for tool in tools
            )
        return snapshot_id

    def save_rejected(
        self,
        *,
        peer_id: str,
        endpoint: str,
        network_policy: str,
        error_code: str,
        now: datetime,
    ) -> UUID:
        snapshot_id = uuid4()
        with self._session_factory.begin() as session:
            session.add(
                McpPeerSnapshotRow(
                    id=str(snapshot_id),
                    peer_id=peer_id,
                    endpoint=endpoint,
                    transport="streamable_http",
                    network_policy=network_policy,
                    protocol_version=None,
                    catalog_revision=str(uuid4()),
                    status="rejected",
                    error_code=error_code[:64],
                    discovered_at=now,
                    expires_at=now,
                )
            )
        return snapshot_id

    @staticmethod
    def _to_snapshot(session: Session, row: McpPeerSnapshotRow) -> McpPeerSnapshot:
        tools = session.scalars(
            select(McpToolSnapshotRow)
            .where(McpToolSnapshotRow.peer_snapshot_id == row.id)
            .order_by(McpToolSnapshotRow.alias)
        ).all()
        return McpPeerSnapshot(
            id=UUID(row.id),
            peer_id=row.peer_id,
            endpoint=row.endpoint,
            protocol_version=row.protocol_version or "",
            catalog_revision=row.catalog_revision,
            discovered_at=row.discovered_at,
            expires_at=row.expires_at,
            tools=tuple(
                McpToolSnapshot(
                    tool_identity=UUID(tool.tool_identity),
                    remote_name=tool.remote_name,
                    alias=tool.alias,
                    label=tool.label,
                    description=tool.description,
                    classification=tool.classification,
                    allowed_roles=tuple(tool.allowed_roles_json),
                    input_schema=tool.input_schema_json,
                    output_schema=tool.output_schema_json,
                    remote_annotations=tool.remote_annotations_json,
                    schema_revision=tool.schema_revision,
                )
                for tool in tools
            ),
        )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
