from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.wazuh.persistence import (
    WazuhAlertRow,
    WazuhCaseDispositionRow,
    WazuhCaseRunRow,
    WazuhReviewCaseRow,
)
from shieldchain.wazuh.schemas import (
    WazuhAlertInput,
    WazuhAlertView,
    WazuhCaseDispositionRequest,
    WazuhCaseDispositionView,
    WazuhFalsePositiveMetricsView,
    WazuhReviewCaseView,
)


class WazuhAlertService:
    """Persist minimized evidence and correlate high-risk alerts into review-only cases."""

    def ingest(
        self,
        session: Session,
        alert: WazuhAlertInput,
        *,
        tenant_id: UUID,
        now: datetime,
        review_min_severity: int,
        review_correlation_window_seconds: int,
    ) -> WazuhAlertView:
        existing = session.scalar(
            select(WazuhAlertRow).where(
                WazuhAlertRow.tenant_id == str(tenant_id),
                WazuhAlertRow.external_id == alert.external_id,
            )
        )
        if existing is not None:
            return self._view(
                existing,
                created=False,
                review_case=self._review_case_for_alert(session, existing),
            )

        row = WazuhAlertRow(
            id=str(uuid4()),
            tenant_id=str(tenant_id),
            external_id=alert.external_id,
            occurred_at=alert.occurred_at,
            severity=alert.severity,
            rule_id=alert.rule_id,
            title=alert.title,
            agent_id=alert.agent_id,
            agent_name=alert.agent_name,
            mitre_ids_json=list(alert.mitre_ids),
            process_name=alert.process_name,
            parent_process_name=alert.parent_process_name,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            destination_port=alert.destination_port,
            evidence_json=dict(alert.evidence),
            received_at=now.astimezone(UTC),
        )
        session.add(row)
        session.flush()
        review_case = None
        if row.severity >= review_min_severity:
            review_case = self._find_or_create_review_case(
                session,
                row,
                now=now,
                correlation_window_seconds=review_correlation_window_seconds,
            )
        return self._view(row, created=True, review_case=review_case)

    def list_recent(self, session: Session, *, tenant_id: UUID, limit: int) -> list[WazuhAlertView]:
        rows = session.scalars(
            select(WazuhAlertRow)
            .where(WazuhAlertRow.tenant_id == str(tenant_id))
            .order_by(WazuhAlertRow.received_at.desc(), WazuhAlertRow.id.desc())
            .limit(limit)
        ).all()
        return [
            self._view(row, created=False, review_case=self._review_case_for_alert(session, row))
            for row in rows
        ]

    def list_review_cases(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        limit: int,
        correlation_window_seconds: int,
    ) -> list[WazuhReviewCaseView]:
        rows = session.scalars(
            select(WazuhReviewCaseRow)
            .where(WazuhReviewCaseRow.tenant_id == str(tenant_id))
            .order_by(WazuhReviewCaseRow.updated_at.desc(), WazuhReviewCaseRow.id.desc())
            .limit(limit * 4)
        ).all()
        shown: dict[tuple[str, str, str], datetime] = {}
        result: list[WazuhReviewCaseView] = []
        for row in rows:
            key = (row.endpoint, row.rule_id, row.title)
            previous = shown.get(key)
            if previous is not None and previous - self._utc(row.created_at) <= timedelta(
                seconds=correlation_window_seconds
            ):
                continue
            shown[key] = self._utc(row.created_at)
            result.append(self._review_case_with_run(session, row))
            if len(result) == limit:
                break
        return result

    def record_disposition(
        self,
        session: Session,
        *,
        case_id: UUID,
        tenant_id: UUID,
        reviewer_id: UUID,
        payload: WazuhCaseDispositionRequest,
        now: datetime,
    ) -> WazuhCaseDispositionView:
        case = session.get(WazuhReviewCaseRow, str(case_id))
        if case is None or case.tenant_id != str(tenant_id):
            raise LookupError("Wazuh review case not found")
        run_id = session.scalar(
            select(WazuhCaseRunRow.run_id).where(
                WazuhCaseRunRow.case_id == str(case_id),
                WazuhCaseRunRow.tenant_id == str(tenant_id),
            )
        )
        if run_id is None:
            raise ValueError("必须先完成智能体调查，才能提交人工定性")
        if payload.suppression_scope != "none" and payload.suppression_expires_at is None:
            raise ValueError("抑制建议必须设置到期时间")
        if payload.suppression_expires_at is not None:
            expires_at = self._utc(payload.suppression_expires_at)
            current = now.astimezone(UTC)
            if expires_at <= current:
                raise ValueError("抑制建议到期时间必须晚于当前时间")
            if expires_at > current + timedelta(days=90):
                raise ValueError("单次抑制建议有效期不能超过 90 天")
        row = WazuhCaseDispositionRow(
            id=str(uuid4()),
            case_id=str(case_id),
            run_id=run_id,
            tenant_id=str(tenant_id),
            decision=payload.decision,
            reason_code=payload.reason_code,
            rationale=payload.rationale.strip(),
            suppression_scope=payload.suppression_scope,
            suppression_expires_at=payload.suppression_expires_at,
            reviewer_id=str(reviewer_id),
            created_at=now.astimezone(UTC),
        )
        session.add(row)
        session.flush()
        return self._disposition_view(row)

    def false_positive_metrics(
        self, session: Session, *, tenant_id: UUID
    ) -> WazuhFalsePositiveMetricsView:
        rows = session.scalars(
            select(WazuhCaseDispositionRow)
            .where(WazuhCaseDispositionRow.tenant_id == str(tenant_id))
            .order_by(
                WazuhCaseDispositionRow.created_at.desc(),
                WazuhCaseDispositionRow.id.desc(),
            )
        ).all()
        latest: dict[str, WazuhCaseDispositionRow] = {}
        for row in rows:
            latest.setdefault(row.case_id, row)
        decisions = tuple(latest.values())
        false_positives = sum(row.decision == "false_positive" for row in decisions)
        true_positives = sum(row.decision == "true_positive" for row in decisions)
        conclusive = false_positives + true_positives
        return WazuhFalsePositiveMetricsView(
            reviewed_cases=len(decisions),
            false_positives=false_positives,
            true_positives=true_positives,
            needs_more_evidence=sum(
                row.decision == "needs_more_evidence" for row in decisions
            ),
            false_positive_rate=false_positives / conclusive if conclusive else None,
            proposed_suppressions=sum(
                row.suppression_scope != "none" for row in decisions
            ),
        )

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _endpoint(alert: WazuhAlertRow) -> str:
        return alert.agent_name or alert.agent_id or "未标识终端"

    @classmethod
    def _view(
        cls,
        row: WazuhAlertRow,
        *,
        created: bool,
        review_case: WazuhReviewCaseView | None = None,
    ) -> WazuhAlertView:
        return WazuhAlertView(
            id=UUID(row.id),
            external_id=row.external_id,
            occurred_at=cls._utc(row.occurred_at),
            severity=row.severity,
            rule_id=row.rule_id,
            title=row.title,
            agent_name=row.agent_name,
            mitre_ids=tuple(row.mitre_ids_json),
            process_name=row.process_name,
            source_ip=row.source_ip,
            destination_ip=row.destination_ip,
            destination_port=row.destination_port,
            received_at=cls._utc(row.received_at),
            created=created,
            review_case=review_case,
        )

    @classmethod
    def _review_case_view(
        cls,
        row: WazuhReviewCaseRow,
        run_id: str | None = None,
        *,
        run_status: str | None = None,
        disposition: WazuhCaseDispositionView | None = None,
    ) -> WazuhReviewCaseView:
        status = "needs_review"
        if run_id is not None:
            if run_status == "completed":
                status = "investigated"
            elif run_status in {"failed", "cancelled"}:
                status = "investigation_failed"
            else:
                status = "investigating"
        return WazuhReviewCaseView(
            id=UUID(row.id),
            tracking_id=f"WAZ-{row.tracking_year}-{row.tracking_sequence:04d}",
            alert_id=UUID(row.alert_id),
            status=status,
            run_id=UUID(run_id) if run_id else None,
            severity=row.severity,
            rule_id=row.rule_id,
            title=row.title,
            endpoint=row.endpoint,
            created_at=cls._utc(row.created_at),
            updated_at=cls._utc(row.updated_at),
            disposition=disposition,
        )

    def _review_case_for_alert(
        self, session: Session, alert: WazuhAlertRow
    ) -> WazuhReviewCaseView | None:
        direct = session.scalar(
            select(WazuhReviewCaseRow).where(WazuhReviewCaseRow.alert_id == alert.id)
        )
        if direct is not None:
            return self._review_case_with_run(session, direct)
        row = session.scalar(
            select(WazuhReviewCaseRow)
            .where(
                WazuhReviewCaseRow.tenant_id == alert.tenant_id,
                WazuhReviewCaseRow.rule_id == alert.rule_id,
                WazuhReviewCaseRow.title == alert.title,
                WazuhReviewCaseRow.endpoint == self._endpoint(alert),
                WazuhReviewCaseRow.status == "needs_review",
            )
            .order_by(WazuhReviewCaseRow.updated_at.desc())
            .limit(1)
        )
        return self._review_case_with_run(session, row) if row is not None else None

    def _review_case_with_run(
        self, session: Session, row: WazuhReviewCaseRow
    ) -> WazuhReviewCaseView:
        run_id = session.scalar(
            select(WazuhCaseRunRow.run_id).where(
                WazuhCaseRunRow.case_id == row.id,
                WazuhCaseRunRow.tenant_id == row.tenant_id,
            )
        )
        run_status = None
        if run_id is not None:
            run_status = session.scalar(
                select(AgentRunRow.status).where(
                    AgentRunRow.id == run_id,
                    AgentRunRow.tenant_id == row.tenant_id,
                )
            )
        disposition = session.scalar(
            select(WazuhCaseDispositionRow)
            .where(
                WazuhCaseDispositionRow.case_id == row.id,
                WazuhCaseDispositionRow.tenant_id == row.tenant_id,
            )
            .order_by(
                WazuhCaseDispositionRow.created_at.desc(),
                WazuhCaseDispositionRow.id.desc(),
            )
            .limit(1)
        )
        return self._review_case_view(
            row,
            run_id,
            run_status=run_status,
            disposition=self._disposition_view(disposition) if disposition else None,
        )

    @classmethod
    def _disposition_view(cls, row: WazuhCaseDispositionRow) -> WazuhCaseDispositionView:
        return WazuhCaseDispositionView(
            id=UUID(row.id),
            case_id=UUID(row.case_id),
            run_id=UUID(row.run_id),
            decision=row.decision,
            reason_code=row.reason_code,
            rationale=row.rationale,
            suppression_scope=row.suppression_scope,
            suppression_status=(
                "proposed_only" if row.suppression_scope != "none" else "not_requested"
            ),
            suppression_expires_at=(
                cls._utc(row.suppression_expires_at)
                if row.suppression_expires_at
                else None
            ),
            reviewer_id=UUID(row.reviewer_id),
            created_at=cls._utc(row.created_at),
        )

    def _find_or_create_review_case(
        self,
        session: Session,
        alert: WazuhAlertRow,
        *,
        now: datetime,
        correlation_window_seconds: int,
    ) -> WazuhReviewCaseView:
        endpoint = self._endpoint(alert)
        candidate = session.scalar(
            select(WazuhReviewCaseRow)
            .where(
                WazuhReviewCaseRow.tenant_id == alert.tenant_id,
                WazuhReviewCaseRow.rule_id == alert.rule_id,
                WazuhReviewCaseRow.title == alert.title,
                WazuhReviewCaseRow.endpoint == endpoint,
                WazuhReviewCaseRow.status == "needs_review",
                WazuhReviewCaseRow.created_at
                >= now.astimezone(UTC) - timedelta(seconds=correlation_window_seconds),
            )
            .order_by(WazuhReviewCaseRow.updated_at.desc())
            .limit(1)
        )
        if candidate is not None:
            candidate.updated_at = now.astimezone(UTC)
            session.flush()
            return self._review_case_view(candidate)
        return self._create_review_case(session, alert, now=now, endpoint=endpoint)

    def _create_review_case(
        self,
        session: Session,
        alert: WazuhAlertRow,
        *,
        now: datetime,
        endpoint: str,
    ) -> WazuhReviewCaseView:
        year = self._utc(alert.occurred_at).year
        sequence = (
            session.scalar(
                select(func.max(WazuhReviewCaseRow.tracking_sequence)).where(
                    WazuhReviewCaseRow.tenant_id == alert.tenant_id,
                    WazuhReviewCaseRow.tracking_year == year,
                )
            )
            or 0
        ) + 1
        row = WazuhReviewCaseRow(
            id=str(uuid4()),
            tenant_id=alert.tenant_id,
            alert_id=alert.id,
            tracking_year=year,
            tracking_sequence=sequence,
            status="needs_review",
            severity=alert.severity,
            rule_id=alert.rule_id,
            title=alert.title,
            endpoint=endpoint,
            created_at=now.astimezone(UTC),
            updated_at=now.astimezone(UTC),
        )
        session.add(row)
        session.flush()
        return self._review_case_view(row)
