from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.wazuh.persistence import (
    WazuhAlertRow,
    WazuhCaseDispositionRow,
    WazuhCaseRunRow,
    WazuhReviewCaseRow,
    WazuhSuppressionMatchRow,
    WazuhSuppressionPolicyRow,
)
from shieldchain.wazuh.schemas import (
    WazuhAlertInput,
    WazuhAlertView,
    WazuhCaseDispositionRequest,
    WazuhCaseDispositionView,
    WazuhFalsePositiveMetricsView,
    WazuhReviewCaseView,
    WazuhSuppressionMatchView,
    WazuhSuppressionPolicyView,
)


class WazuhAlertService:
    """Persist minimized evidence and correlate high-risk alerts into review-only cases."""

    _active_run_statuses = {
        "pending",
        "running",
        "awaiting_approval",
        "awaiting_execution",
        "verifying",
    }
    _stale_run_after = timedelta(minutes=15)

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
            suppression = self._suppression_for_alert(session, existing)
            return self._view(
                existing,
                created=False,
                review_case=(
                    None
                    if suppression is not None
                    else self._review_case_for_alert(session, existing)
                ),
                suppression=suppression,
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
        suppression = self._apply_matching_suppression(session, row, now=now)
        review_case = None
        if suppression is None and row.severity >= review_min_severity:
            review_case = self._find_or_create_review_case(
                session,
                row,
                now=now,
                correlation_window_seconds=review_correlation_window_seconds,
            )
        return self._view(
            row,
            created=True,
            review_case=review_case,
            suppression=suppression,
        )

    def list_recent(self, session: Session, *, tenant_id: UUID, limit: int) -> list[WazuhAlertView]:
        rows = session.scalars(
            select(WazuhAlertRow)
            .where(WazuhAlertRow.tenant_id == str(tenant_id))
            .order_by(WazuhAlertRow.received_at.desc(), WazuhAlertRow.id.desc())
            .limit(limit)
        ).all()
        return [
            self._view(
                row,
                created=False,
                review_case=self._review_case_for_alert(session, row),
                suppression=self._suppression_for_alert(session, row),
            )
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

    def delete_review_case(
        self,
        session: Session,
        *,
        case_id: UUID,
        tenant_id: UUID,
    ) -> bool:
        """Remove one case from the live queue while retaining its immutable run evidence."""

        case = session.scalar(
            select(WazuhReviewCaseRow).where(
                WazuhReviewCaseRow.id == str(case_id),
                WazuhReviewCaseRow.tenant_id == str(tenant_id),
            )
        )
        if case is None:
            return False
        run = session.scalar(
            select(AgentRunRow)
            .join(WazuhCaseRunRow, WazuhCaseRunRow.run_id == AgentRunRow.id)
            .where(
                WazuhCaseRunRow.case_id == case.id,
                WazuhCaseRunRow.tenant_id == case.tenant_id,
                AgentRunRow.tenant_id == case.tenant_id,
            )
        )
        run_is_active = run is not None and run.status in self._active_run_statuses
        run_is_stale = (
            run is not None
            and datetime.now(UTC) - self._utc(run.updated_at) > self._stale_run_after
        )
        if run_is_active and not run_is_stale:
            raise ValueError("智能体调查或处置仍在进行，暂时不能删除该告警")
        session.execute(
            delete(WazuhCaseDispositionRow).where(
                WazuhCaseDispositionRow.case_id == case.id,
                WazuhCaseDispositionRow.tenant_id == case.tenant_id,
            )
        )
        session.delete(case)
        session.flush()
        return True

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
        active_policies = session.scalars(
            select(WazuhSuppressionPolicyRow).where(
                WazuhSuppressionPolicyRow.tenant_id == str(tenant_id),
                WazuhSuppressionPolicyRow.source_case_id == str(case_id),
                WazuhSuppressionPolicyRow.status == "active",
            )
        ).all()
        for policy in active_policies:
            policy.status = "revoked"
            policy.revoked_at = now.astimezone(UTC)
        session.flush()
        return self._disposition_view(row)

    def approve_suppression(
        self,
        session: Session,
        *,
        case_id: UUID,
        tenant_id: UUID,
        approver_id: UUID,
        now: datetime,
    ) -> WazuhSuppressionPolicyView:
        """Activate the latest reviewed false-positive proposal for future ingestion."""

        case = session.scalar(
            select(WazuhReviewCaseRow).where(
                WazuhReviewCaseRow.id == str(case_id),
                WazuhReviewCaseRow.tenant_id == str(tenant_id),
            )
        )
        if case is None:
            raise LookupError("Wazuh review case not found")
        disposition = session.scalar(
            select(WazuhCaseDispositionRow)
            .where(
                WazuhCaseDispositionRow.case_id == case.id,
                WazuhCaseDispositionRow.tenant_id == case.tenant_id,
            )
            .order_by(
                WazuhCaseDispositionRow.created_at.desc(),
                WazuhCaseDispositionRow.id.desc(),
            )
            .limit(1)
        )
        if disposition is None:
            raise ValueError("必须先提交人工误报结论和抑制建议")
        if disposition.decision != "false_positive":
            raise ValueError("只有已确认误报的案件可以启用抑制策略")
        if disposition.suppression_scope == "none":
            raise ValueError("当前人工结论没有可审批的抑制范围")
        if disposition.suppression_expires_at is None:
            raise ValueError("抑制策略缺少到期时间")
        current = now.astimezone(UTC)
        expires_at = self._utc(disposition.suppression_expires_at)
        if expires_at <= current:
            raise ValueError("抑制建议已经过期，请重新提交人工定性")
        existing = session.scalar(
            select(WazuhSuppressionPolicyRow).where(
                WazuhSuppressionPolicyRow.tenant_id == case.tenant_id,
                WazuhSuppressionPolicyRow.source_disposition_id == disposition.id,
            )
        )
        if existing is not None:
            return self._suppression_policy_view(existing, now=current)
        previous = session.scalars(
            select(WazuhSuppressionPolicyRow).where(
                WazuhSuppressionPolicyRow.tenant_id == case.tenant_id,
                WazuhSuppressionPolicyRow.source_case_id == case.id,
                WazuhSuppressionPolicyRow.status == "active",
            )
        ).all()
        for policy in previous:
            policy.status = "revoked"
            policy.revoked_at = current
        policy = WazuhSuppressionPolicyRow(
            id=str(uuid4()),
            tenant_id=case.tenant_id,
            source_case_id=case.id,
            source_disposition_id=disposition.id,
            rule_id=case.rule_id,
            endpoint=(
                case.endpoint
                if disposition.suppression_scope == "same_rule_endpoint"
                else None
            ),
            scope=disposition.suppression_scope,
            status="active",
            rationale=disposition.rationale,
            expires_at=expires_at,
            approved_by=str(approver_id),
            approved_at=current,
            revoked_at=None,
        )
        session.add(policy)
        session.flush()
        return self._suppression_policy_view(policy, now=current)

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
        policies = session.scalars(
            select(WazuhSuppressionPolicyRow).where(
                WazuhSuppressionPolicyRow.tenant_id == str(tenant_id)
            )
        ).all()
        policy_dispositions = {row.source_disposition_id for row in policies}
        current = datetime.now(UTC)
        return WazuhFalsePositiveMetricsView(
            reviewed_cases=len(decisions),
            false_positives=false_positives,
            true_positives=true_positives,
            needs_more_evidence=sum(
                row.decision == "needs_more_evidence" for row in decisions
            ),
            false_positive_rate=false_positives / conclusive if conclusive else None,
            proposed_suppressions=sum(
                row.suppression_scope != "none" and row.id not in policy_dispositions
                for row in decisions
            ),
            active_suppressions=sum(
                row.status == "active" and self._utc(row.expires_at) > current
                for row in policies
            ),
            suppressed_alerts=session.scalar(
                select(func.count(WazuhSuppressionMatchRow.id)).where(
                    WazuhSuppressionMatchRow.tenant_id == str(tenant_id)
                )
            )
            or 0,
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
        suppression: WazuhSuppressionMatchView | None = None,
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
            suppression=suppression,
        )

    @classmethod
    def _review_case_view(
        cls,
        row: WazuhReviewCaseRow,
        run_id: str | None = None,
        *,
        run_status: str | None = None,
        run_updated_at: datetime | None = None,
        disposition: WazuhCaseDispositionView | None = None,
    ) -> WazuhReviewCaseView:
        status = "needs_review"
        if run_id is not None:
            if run_status == "completed":
                status = "investigated"
            elif run_status in {"failed", "cancelled", "needs_review"}:
                status = "investigation_failed"
            elif (
                run_status in cls._active_run_statuses
                and run_updated_at is not None
                and datetime.now(UTC) - cls._utc(run_updated_at) > cls._stale_run_after
            ):
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
        if self._suppression_for_alert(session, alert) is not None:
            return None
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
        run_updated_at = None
        if run_id is not None:
            run = session.scalar(
                select(AgentRunRow).where(
                    AgentRunRow.id == run_id,
                    AgentRunRow.tenant_id == row.tenant_id,
                )
            )
            if run is not None:
                run_status = run.status
                run_updated_at = run.updated_at
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
        policy = None
        if disposition is not None:
            policy = session.scalar(
                select(WazuhSuppressionPolicyRow).where(
                    WazuhSuppressionPolicyRow.tenant_id == row.tenant_id,
                    WazuhSuppressionPolicyRow.source_disposition_id == disposition.id,
                )
            )
        return self._review_case_view(
            row,
            run_id,
            run_status=run_status,
            run_updated_at=run_updated_at,
            disposition=(
                self._disposition_view(disposition, policy=policy)
                if disposition
                else None
            ),
        )

    @classmethod
    def _disposition_view(
        cls,
        row: WazuhCaseDispositionRow,
        *,
        policy: WazuhSuppressionPolicyRow | None = None,
    ) -> WazuhCaseDispositionView:
        if row.suppression_scope == "none":
            suppression_status = "not_requested"
        elif policy is None:
            suppression_status = "proposed_only"
        elif policy.status == "revoked":
            suppression_status = "revoked"
        elif cls._utc(policy.expires_at) <= datetime.now(UTC):
            suppression_status = "expired"
        else:
            suppression_status = "active"
        return WazuhCaseDispositionView(
            id=UUID(row.id),
            case_id=UUID(row.case_id),
            run_id=UUID(row.run_id),
            decision=row.decision,
            reason_code=row.reason_code,
            rationale=row.rationale,
            suppression_scope=row.suppression_scope,
            suppression_status=suppression_status,
            suppression_expires_at=(
                cls._utc(row.suppression_expires_at)
                if row.suppression_expires_at
                else None
            ),
            reviewer_id=UUID(row.reviewer_id),
            created_at=cls._utc(row.created_at),
        )

    @classmethod
    def _suppression_policy_view(
        cls, row: WazuhSuppressionPolicyRow, *, now: datetime | None = None
    ) -> WazuhSuppressionPolicyView:
        current = now or datetime.now(UTC)
        status = row.status
        if status == "active" and cls._utc(row.expires_at) <= current:
            status = "expired"
        return WazuhSuppressionPolicyView(
            id=UUID(row.id),
            source_case_id=UUID(row.source_case_id),
            source_disposition_id=UUID(row.source_disposition_id),
            rule_id=row.rule_id,
            endpoint=row.endpoint,
            scope=row.scope,
            status=status,
            rationale=row.rationale,
            expires_at=cls._utc(row.expires_at),
            approved_by=UUID(row.approved_by),
            approved_at=cls._utc(row.approved_at),
        )

    def _apply_matching_suppression(
        self, session: Session, alert: WazuhAlertRow, *, now: datetime
    ) -> WazuhSuppressionMatchView | None:
        current = now.astimezone(UTC)
        endpoint = self._endpoint(alert)
        policies = session.scalars(
            select(WazuhSuppressionPolicyRow)
            .where(
                WazuhSuppressionPolicyRow.tenant_id == alert.tenant_id,
                WazuhSuppressionPolicyRow.rule_id == alert.rule_id,
                WazuhSuppressionPolicyRow.status == "active",
                WazuhSuppressionPolicyRow.expires_at > current,
            )
            .order_by(WazuhSuppressionPolicyRow.approved_at.desc())
        ).all()
        policy = next(
            (
                item
                for item in policies
                if item.scope == "same_rule"
                or (item.scope == "same_rule_endpoint" and item.endpoint == endpoint)
            ),
            None,
        )
        if policy is None:
            return None
        match = WazuhSuppressionMatchRow(
            id=str(uuid4()),
            tenant_id=alert.tenant_id,
            policy_id=policy.id,
            alert_id=alert.id,
            rule_id=alert.rule_id,
            endpoint=endpoint,
            matched_at=current,
        )
        session.add(match)
        session.flush()
        return self._suppression_match_view(match, policy)

    def _suppression_for_alert(
        self, session: Session, alert: WazuhAlertRow
    ) -> WazuhSuppressionMatchView | None:
        match = session.scalar(
            select(WazuhSuppressionMatchRow).where(
                WazuhSuppressionMatchRow.tenant_id == alert.tenant_id,
                WazuhSuppressionMatchRow.alert_id == alert.id,
            )
        )
        if match is None:
            return None
        policy = session.scalar(
            select(WazuhSuppressionPolicyRow).where(
                WazuhSuppressionPolicyRow.tenant_id == alert.tenant_id,
                WazuhSuppressionPolicyRow.id == match.policy_id,
            )
        )
        return self._suppression_match_view(match, policy) if policy is not None else None

    @classmethod
    def _suppression_match_view(
        cls, match: WazuhSuppressionMatchRow, policy: WazuhSuppressionPolicyRow
    ) -> WazuhSuppressionMatchView:
        return WazuhSuppressionMatchView(
            id=UUID(match.id),
            policy_id=UUID(policy.id),
            scope=policy.scope,
            rule_id=match.rule_id,
            endpoint=match.endpoint,
            matched_at=cls._utc(match.matched_at),
            expires_at=cls._utc(policy.expires_at),
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
