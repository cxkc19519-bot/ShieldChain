from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from .agent import VulnerabilityTriageAgent
from .persistence import VulnerabilityFindingRow, VulnerabilityWorkflowEventRow
from .schemas import (
    VulnerabilityChangeRequest,
    VulnerabilityDecisionRequest,
    VulnerabilityFindingIngestRequest,
    VulnerabilityFindingIngestResponse,
    VulnerabilityFindingListResponse,
    VulnerabilityFindingView,
    VulnerabilityImplementationRequest,
    VulnerabilityMetricsView,
    VulnerabilityMutationView,
    VulnerabilityTriageRequest,
    VulnerabilityVerificationRequest,
    VulnerabilityWorkflowEventView,
)


class VulnerabilityWorkflowError(RuntimeError):
    pass


class VulnerabilityNotFound(VulnerabilityWorkflowError):
    pass


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


class VulnerabilityWorkflowService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        agent: VulnerabilityTriageAgent,
        *,
        scanner_token: str,
        tenant_id: UUID,
        principal_id: UUID,
    ) -> None:
        self._sessions = sessions
        self._agent = agent
        self._scanner_token = scanner_token
        self._tenant_id = str(tenant_id)
        self._principal_id = str(principal_id)

    def scanner_authorized(self, token: str | None) -> bool:
        return bool(
            self._scanner_token and token and secrets.compare_digest(self._scanner_token, token)
        )

    def ingest(
        self, request: VulnerabilityFindingIngestRequest
    ) -> VulnerabilityFindingIngestResponse:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            existing = session.scalar(
                select(VulnerabilityFindingRow).where(
                    VulnerabilityFindingRow.tenant_id == self._tenant_id,
                    VulnerabilityFindingRow.scanner == request.scanner,
                    VulnerabilityFindingRow.external_id == request.external_id,
                )
            )
            if existing is not None:
                if _utc(request.observed_at) > _utc(existing.last_seen_at):
                    existing.last_seen_at = request.observed_at
                    existing.updated_at = now
                return VulnerabilityFindingIngestResponse(
                    created=False, finding=self._view(session, existing)
                )
            row = VulnerabilityFindingRow(
                id=str(uuid4()),
                tenant_id=self._tenant_id,
                status="new",
                scanner=request.scanner,
                external_id=request.external_id,
                asset_id=request.asset_id,
                asset_name=request.asset_name,
                cve_id=request.cve_id,
                severity=request.severity,
                cvss_score=request.cvss_score,
                package_name=request.package_name,
                installed_version=request.installed_version,
                fixed_version=request.fixed_version,
                evidence_json=request.evidence,
                first_seen_at=request.observed_at,
                last_seen_at=request.observed_at,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            self._event(
                session,
                row,
                event_type="finding_ingested",
                actor_type="scanner",
                actor_id=request.scanner,
                from_status=None,
                to_status="new",
                reason_code="scanner_observation",
                summary="扫描器提交新的漏洞发现，尚未完成人工影响确认。",
                details={"evidence": request.evidence},
                now=now,
            )
            return VulnerabilityFindingIngestResponse(
                created=True, finding=self._view(session, row)
            )

    def list(self) -> VulnerabilityFindingListResponse:
        with self._sessions() as session:
            rows = session.scalars(
                select(VulnerabilityFindingRow)
                .where(VulnerabilityFindingRow.tenant_id == self._tenant_id)
                .order_by(VulnerabilityFindingRow.updated_at.desc())
                .limit(200)
            ).all()
            return VulnerabilityFindingListResponse(
                items=[self._view(session, row) for row in rows]
            )

    def get(self, finding_id: UUID) -> VulnerabilityFindingView:
        with self._sessions() as session:
            return self._view(session, self._get(session, finding_id))

    async def triage(
        self, finding_id: UUID, request: VulnerabilityTriageRequest
    ) -> VulnerabilityMutationView:
        with self._sessions() as session:
            finding = self._get(session, finding_id)
            if finding.status not in {"new", "triaged"}:
                raise VulnerabilityWorkflowError("finding cannot be triaged in its current status")
            result = await self._agent.analyze(finding, request.business_context)
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            if row.status not in {"new", "triaged"}:
                raise VulnerabilityWorkflowError("finding changed while agent was analyzing it")
            previous = row.status
            row.status = "triaged"
            row.updated_at = now
            event = self._event(
                session,
                row,
                event_type="agent_triage_completed",
                actor_type="agent",
                actor_id="vulnerability_triage",
                from_status=previous,
                to_status="triaged",
                reason_code="model_assessment"
                if result.status == "completed"
                else "conservative_fallback",
                summary=result.summary,
                details={
                    "agent_name": "漏洞研判智能体",
                    "agent_status": result.status,
                    "model": result.model,
                    "priority": result.priority,
                    "affected_assessment": result.affected_assessment,
                    "remediation": result.remediation,
                    "verification": result.verification,
                    "evidence_gaps": result.evidence_gaps,
                    "knowledge_citations": result.knowledge_citations,
                },
                now=now,
            )
            return VulnerabilityMutationView(
                finding=self._view(session, row), event=self._event_view(event)
            )

    def decide(
        self, finding_id: UUID, request: VulnerabilityDecisionRequest
    ) -> VulnerabilityMutationView:
        now = datetime.now(UTC)
        if request.risk_expires_at is not None:
            expires = _utc(request.risk_expires_at)
            if expires <= now or expires > now + timedelta(days=365):
                raise VulnerabilityWorkflowError("risk acceptance expiry must be within 365 days")
        target, event_type = {
            "approve_remediation": ("remediation_approved", "remediation_approved"),
            "accept_risk": ("accepted_risk", "risk_accepted"),
            "mark_not_affected": ("closed", "finding_not_affected"),
        }[request.outcome]
        return self._transition(
            finding_id,
            allowed={"triaged"},
            target=target,
            event_type=event_type,
            reason_code=request.reason_code,
            summary=request.rationale,
            details={
                "risk_expires_at": request.risk_expires_at.isoformat()
                if request.risk_expires_at
                else None
            },
        )

    def start_change(
        self, finding_id: UUID, request: VulnerabilityChangeRequest
    ) -> VulnerabilityMutationView:
        return self._transition(
            finding_id,
            allowed={"remediation_approved"},
            target="remediation_in_progress",
            event_type="remediation_started",
            reason_code="approved_change",
            summary=request.plan_summary,
            details={
                "change_ticket": request.change_ticket,
                "implementer": request.implementer,
                "planned_at": request.planned_at.isoformat(),
            },
        )

    def complete_change(
        self, finding_id: UUID, request: VulnerabilityImplementationRequest
    ) -> VulnerabilityMutationView:
        return self._transition(
            finding_id,
            allowed={"remediation_in_progress"},
            target="verification_pending",
            event_type="remediation_completed",
            reason_code="implementation_recorded",
            summary=request.implementation_summary,
            details={
                "change_ticket": request.change_ticket,
                "evidence_references": request.evidence_references,
            },
        )

    def verify(
        self, finding_id: UUID, request: VulnerabilityVerificationRequest
    ) -> VulnerabilityMutationView:
        passed = request.result == "passed"
        return self._transition(
            finding_id,
            allowed={"verification_pending"},
            target="closed" if passed else "triaged",
            event_type="verification_passed" if passed else "verification_failed",
            reason_code="scanner_retest_passed" if passed else "scanner_retest_failed",
            summary=request.summary,
            details={
                "scanner": request.scanner,
                "observed_version": request.observed_version,
                "evidence_references": request.evidence_references,
            },
        )

    def metrics(self) -> VulnerabilityMetricsView:
        with self._sessions() as session:
            rows = session.execute(
                select(
                    VulnerabilityFindingRow.status, VulnerabilityFindingRow.severity, func.count()
                )
                .where(VulnerabilityFindingRow.tenant_id == self._tenant_id)
                .group_by(VulnerabilityFindingRow.status, VulnerabilityFindingRow.severity)
            ).all()

        def count(statuses: set[str]) -> int:
            return sum(number for status, _severity, number in rows if status in statuses)

        open_statuses = {
            "new",
            "triaged",
            "remediation_approved",
            "remediation_in_progress",
            "verification_pending",
        }
        return VulnerabilityMetricsView(
            total=sum(number for _status, _severity, number in rows),
            open=count(open_statuses),
            critical_open=sum(
                number
                for status, severity, number in rows
                if status in open_statuses and severity == "critical"
            ),
            awaiting_approval=count({"triaged"}),
            verification_pending=count({"verification_pending"}),
            closed=count({"closed"}),
            accepted_risk=count({"accepted_risk"}),
        )

    def _transition(
        self,
        finding_id: UUID,
        *,
        allowed: set[str],
        target: str,
        event_type: str,
        reason_code: str,
        summary: str,
        details: dict[str, object],
    ) -> VulnerabilityMutationView:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            if row.status not in allowed:
                raise VulnerabilityWorkflowError(f"transition from {row.status} is not allowed")
            previous = row.status
            row.status = target
            row.updated_at = now
            event = self._event(
                session,
                row,
                event_type=event_type,
                actor_type="human",
                actor_id=self._principal_id,
                from_status=previous,
                to_status=target,
                reason_code=reason_code,
                summary=summary,
                details=details,
                now=now,
            )
            return VulnerabilityMutationView(
                finding=self._view(session, row), event=self._event_view(event)
            )

    def _get(self, session: Session, finding_id: UUID) -> VulnerabilityFindingRow:
        row = session.scalar(
            select(VulnerabilityFindingRow).where(
                VulnerabilityFindingRow.id == str(finding_id),
                VulnerabilityFindingRow.tenant_id == self._tenant_id,
            )
        )
        if row is None:
            raise VulnerabilityNotFound("vulnerability finding not found")
        return row

    def _view(self, session: Session, row: VulnerabilityFindingRow) -> VulnerabilityFindingView:
        events = list(
            session.scalars(
                select(VulnerabilityWorkflowEventRow)
                .where(
                    VulnerabilityWorkflowEventRow.tenant_id == self._tenant_id,
                    VulnerabilityWorkflowEventRow.finding_id == row.id,
                )
                .order_by(
                    VulnerabilityWorkflowEventRow.created_at, VulnerabilityWorkflowEventRow.id
                )
            )
        )
        views = [self._event_view(item) for item in events]
        latest = next(
            (item for item in reversed(views) if item.event_type == "agent_triage_completed"), None
        )
        return VulnerabilityFindingView(
            id=UUID(row.id),
            scanner=row.scanner,
            external_id=row.external_id,
            asset_id=row.asset_id,
            asset_name=row.asset_name,
            cve_id=row.cve_id,
            severity=row.severity,
            cvss_score=row.cvss_score,
            package_name=row.package_name,
            installed_version=row.installed_version,
            fixed_version=row.fixed_version,
            status=row.status,
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
            latest_triage=latest,
            events=views,
        )

    @staticmethod
    def _event(
        session: Session,
        row: VulnerabilityFindingRow,
        *,
        event_type: str,
        actor_type: str,
        actor_id: str,
        from_status: str | None,
        to_status: str,
        reason_code: str,
        summary: str,
        details: dict[str, object],
        now: datetime,
    ) -> VulnerabilityWorkflowEventRow:
        event = VulnerabilityWorkflowEventRow(
            id=str(uuid4()),
            finding_id=row.id,
            tenant_id=row.tenant_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            from_status=from_status,
            to_status=to_status,
            reason_code=reason_code,
            summary=summary,
            details_json=details,
            created_at=now,
        )
        session.add(event)
        session.flush()
        return event

    @staticmethod
    def _event_view(row: VulnerabilityWorkflowEventRow) -> VulnerabilityWorkflowEventView:
        return VulnerabilityWorkflowEventView(
            id=UUID(row.id),
            event_type=row.event_type,
            actor_type=row.actor_type,
            from_status=row.from_status,
            to_status=row.to_status,
            reason_code=row.reason_code,
            summary=row.summary,
            details=row.details_json,
            created_at=row.created_at,
        )
