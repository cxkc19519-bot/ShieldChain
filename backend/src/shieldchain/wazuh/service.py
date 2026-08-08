from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from shieldchain.wazuh.persistence import WazuhAlertRow, WazuhReviewCaseRow
from shieldchain.wazuh.schemas import WazuhAlertInput, WazuhAlertView, WazuhReviewCaseView


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
            result.append(self._review_case_view(row))
            if len(result) == limit:
                break
        return result

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
    def _review_case_view(cls, row: WazuhReviewCaseRow) -> WazuhReviewCaseView:
        return WazuhReviewCaseView(
            id=UUID(row.id),
            tracking_id=f"WAZ-{row.tracking_year}-{row.tracking_sequence:04d}",
            alert_id=UUID(row.alert_id),
            severity=row.severity,
            rule_id=row.rule_id,
            title=row.title,
            endpoint=row.endpoint,
            created_at=cls._utc(row.created_at),
            updated_at=cls._utc(row.updated_at),
        )

    def _review_case_for_alert(
        self, session: Session, alert: WazuhAlertRow
    ) -> WazuhReviewCaseView | None:
        direct = session.scalar(
            select(WazuhReviewCaseRow).where(WazuhReviewCaseRow.alert_id == alert.id)
        )
        if direct is not None:
            return self._review_case_view(direct)
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
        return self._review_case_view(row) if row is not None else None

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
