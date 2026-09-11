from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.operations.persistence import OperationsRunRow
from shieldchain.operations.schemas import OperationsReportRequest, OperationsReportView
from shieldchain.operations.service import SecurityOperationsReportAgent
from shieldchain.wazuh.persistence import WazuhAlertRow, WazuhCaseRunRow, WazuhReviewCaseRow
from shieldchain.wazuh.schemas import (
    WazuhAlertInput,
    WazuhAlertListResponse,
    WazuhAlertView,
    WazuhCaseDispositionRequest,
    WazuhCaseDispositionView,
    WazuhFalsePositiveMetricsView,
    WazuhInvestigationRequest,
    WazuhReviewCaseListResponse,
    WazuhReviewCaseView,
    WazuhSuppressionPolicyView,
    WazuhTriageAssessmentView,
)
from shieldchain.wazuh.service import WazuhAlertService

router = APIRouter(prefix="/integrations/wazuh", tags=["wazuh"])
logger = structlog.get_logger(__name__)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _service(request: Request) -> WazuhAlertService:
    return cast(WazuhAlertService, request.app.state.wazuh_alert_service)


def _sessions(request: Request) -> sessionmaker[Session]:
    return cast(sessionmaker[Session], request.app.state.incident_session_factory)


def _tenant_id(request: Request) -> UUID:
    return cast(UUID, request.app.state.rag_demo_tenant_id)


def _principal_id(request: Request) -> UUID:
    return cast(UUID, request.app.state.rag_demo_principal_id)


def _operations_agent(request: Request) -> SecurityOperationsReportAgent:
    return cast(SecurityOperationsReportAgent, request.app.state.security_operations_report_agent)


def _with_triage_assessment(
    request: Request, session: Session, item: WazuhReviewCaseView
) -> WazuhReviewCaseView:
    if item.run_id is None:
        return item
    report_id = session.scalar(
        select(OperationsRunRow.report_id).where(
            OperationsRunRow.run_id == str(item.run_id),
            OperationsRunRow.tenant_id == str(_tenant_id(request)),
        )
    )
    report = _operations_agent(request).get(report_id) if report_id else None
    if report is None:
        return item
    triage = next((role for role in report.collaboration if role.role == "alert_triage"), None)
    if triage is None:
        return item
    return item.model_copy(
        update={
            "triage_assessment": WazuhTriageAssessmentView(
                run_id=item.run_id,
                model=report.model,
                summary=triage.summary,
                decision_reason=triage.decision_reason,
            )
        }
    )


def _authorized(request: Request, token: str | None) -> None:
    configured = _settings(request).wazuh_webhook_token.get_secret_value()
    if not configured:
        raise ApiError("wazuh_ingestion_unconfigured", "Wazuh ingestion is not configured", 503)
    if token is None or not hmac.compare_digest(token, configured):
        raise ApiError("wazuh_ingestion_unauthorized", "Wazuh webhook token is invalid", 401)


async def _run_automatic_investigation(
    agent: SecurityOperationsReportAgent,
    *,
    case_id: UUID,
    occurred_at: datetime,
    request_id: str,
) -> None:
    try:
        await agent.generate(
            OperationsReportRequest(
                start_at=occurred_at - timedelta(minutes=5),
                end_at=occurred_at + timedelta(minutes=5),
                wazuh_case_id=case_id,
                rule_ttl_seconds=60,
            ),
            request_id=request_id,
        )
        logger.info("wazuh_automatic_investigation_completed", case_id=str(case_id))
    except ValueError as error:
        # Correlated alerts may schedule the same case concurrently. The first
        # run owns the case; later attempts stop at the unique case binding.
        logger.info(
            "wazuh_automatic_investigation_skipped",
            case_id=str(case_id),
            reason=str(error),
        )
    except Exception as error:
        logger.error(
            "wazuh_automatic_investigation_failed",
            case_id=str(case_id),
            error_type=type(error).__name__,
            error=str(error)[:500],
        )


@router.post("/alerts", status_code=status.HTTP_202_ACCEPTED, response_model=WazuhAlertView)
def ingest_alert(
    payload: WazuhAlertInput,
    request: Request,
    background_tasks: BackgroundTasks,
    x_shieldchain_wazuh_token: str | None = Header(default=None),
) -> WazuhAlertView:
    """Accept evidence and optionally queue a read-only agent investigation."""
    _authorized(request, x_shieldchain_wazuh_token)
    with _sessions(request).begin() as session:
        result = _service(request).ingest(
            session,
            payload,
            tenant_id=_tenant_id(request),
            now=datetime.now(UTC),
            review_min_severity=_settings(request).wazuh_review_min_severity,
            review_correlation_window_seconds=_settings(
                request
            ).wazuh_review_correlation_window_seconds,
        )
    if (
        _settings(request).wazuh_auto_investigation_enabled
        and result.created
        and result.review_case is not None
        and result.review_case.run_id is None
    ):
        background_tasks.add_task(
            _run_automatic_investigation,
            _operations_agent(request),
            case_id=result.review_case.id,
            occurred_at=_service(request)._utc(payload.occurred_at),
            request_id=f"{request.state.request_id}:auto-investigation",
        )
    return result


@router.get("/alerts", response_model=WazuhAlertListResponse)
def list_alerts(
    request: Request, limit: int = Query(default=50, ge=1, le=200)
) -> WazuhAlertListResponse:
    with _sessions(request)() as session:
        return WazuhAlertListResponse(
            items=_service(request).list_recent(session, tenant_id=_tenant_id(request), limit=limit)
        )


@router.get("/cases", response_model=WazuhReviewCaseListResponse)
def list_review_cases(
    request: Request, limit: int = Query(default=50, ge=1, le=200)
) -> WazuhReviewCaseListResponse:
    with _sessions(request)() as session:
        items = _service(request).list_review_cases(
            session,
            tenant_id=_tenant_id(request),
            limit=limit,
            correlation_window_seconds=_settings(
                request
            ).wazuh_review_correlation_window_seconds,
        )
        return WazuhReviewCaseListResponse(
            items=[_with_triage_assessment(request, session, item) for item in items]
        )


@router.get("/false-positive-metrics", response_model=WazuhFalsePositiveMetricsView)
def false_positive_metrics(request: Request) -> WazuhFalsePositiveMetricsView:
    with _sessions(request)() as session:
        return _service(request).false_positive_metrics(session, tenant_id=_tenant_id(request))


@router.delete("/cases/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_review_case(case_id: UUID, request: Request) -> Response:
    report_id: str | None = None
    try:
        with _sessions(request).begin() as session:
            report_id = session.scalar(
                select(OperationsRunRow.report_id)
                .join(WazuhCaseRunRow, WazuhCaseRunRow.run_id == OperationsRunRow.run_id)
                .where(
                    WazuhCaseRunRow.case_id == str(case_id),
                    WazuhCaseRunRow.tenant_id == str(_tenant_id(request)),
                    OperationsRunRow.tenant_id == str(_tenant_id(request)),
                )
            )
            deleted = _service(request).delete_review_case(
                session,
                case_id=case_id,
                tenant_id=_tenant_id(request),
            )
            if not deleted:
                raise ApiError("wazuh_case_not_found", "Wazuh review case not found", 404)
    except ValueError as error:
        raise ApiError("wazuh_case_delete_rejected", str(error), 409) from None
    if report_id is not None:
        _operations_agent(request).delete(report_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/cases/{case_id}/disposition",
    status_code=status.HTTP_201_CREATED,
    response_model=WazuhCaseDispositionView,
)
def record_case_disposition(
    case_id: UUID,
    payload: WazuhCaseDispositionRequest,
    request: Request,
) -> WazuhCaseDispositionView:
    try:
        with _sessions(request).begin() as session:
            return _service(request).record_disposition(
                session,
                case_id=case_id,
                tenant_id=_tenant_id(request),
                reviewer_id=_principal_id(request),
                payload=payload,
                now=datetime.now(UTC),
            )
    except LookupError:
        raise ApiError("wazuh_case_not_found", "Wazuh review case not found", 404) from None
    except ValueError as error:
        raise ApiError("wazuh_disposition_rejected", str(error), 409) from None


@router.post(
    "/cases/{case_id}/suppression/approve",
    status_code=status.HTTP_201_CREATED,
    response_model=WazuhSuppressionPolicyView,
)
def approve_case_suppression(
    case_id: UUID,
    request: Request,
) -> WazuhSuppressionPolicyView:
    """Approve and activate the latest time-bounded false-positive proposal."""

    try:
        with _sessions(request).begin() as session:
            return _service(request).approve_suppression(
                session,
                case_id=case_id,
                tenant_id=_tenant_id(request),
                approver_id=_principal_id(request),
                now=datetime.now(UTC),
            )
    except LookupError:
        raise ApiError("wazuh_case_not_found", "Wazuh review case not found", 404) from None
    except ValueError as error:
        raise ApiError("wazuh_suppression_rejected", str(error), 409) from None


@router.post(
    "/cases/{case_id}/investigate",
    status_code=status.HTTP_201_CREATED,
    response_model=OperationsReportView,
)
async def investigate_review_case(
    case_id: UUID,
    payload: WazuhInvestigationRequest,
    request: Request,
) -> OperationsReportView:
    """Manual fallback for cases that do not yet have an automatic run."""

    with _sessions(request)() as session:
        case = session.get(WazuhReviewCaseRow, str(case_id))
        if case is None or case.tenant_id != str(_tenant_id(request)):
            raise ApiError("wazuh_case_not_found", "Wazuh review case not found", 404)
        alert = session.get(WazuhAlertRow, case.alert_id)
        if alert is None or alert.tenant_id != case.tenant_id:
            raise ApiError("wazuh_case_evidence_missing", "Wazuh case evidence is missing", 409)
        occurred_at = _service(request)._utc(alert.occurred_at)
    try:
        return await _operations_agent(request).generate(
            OperationsReportRequest(
                start_at=occurred_at - timedelta(minutes=5),
                end_at=occurred_at + timedelta(minutes=5),
                wazuh_case_id=case_id,
                rule_ttl_seconds=payload.rule_ttl_seconds,
            ),
            request_id=str(request.state.request_id),
        )
    except ValueError as error:
        raise ApiError("wazuh_investigation_rejected", str(error), 409) from None
