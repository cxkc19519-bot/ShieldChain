from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request, status
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.operations.schemas import OperationsReportRequest, OperationsReportView
from shieldchain.operations.service import SecurityOperationsReportAgent
from shieldchain.wazuh.persistence import WazuhAlertRow, WazuhReviewCaseRow
from shieldchain.wazuh.schemas import (
    WazuhAlertInput,
    WazuhAlertListResponse,
    WazuhAlertView,
    WazuhInvestigationRequest,
    WazuhReviewCaseListResponse,
)
from shieldchain.wazuh.service import WazuhAlertService

router = APIRouter(prefix="/integrations/wazuh", tags=["wazuh"])


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _service(request: Request) -> WazuhAlertService:
    return cast(WazuhAlertService, request.app.state.wazuh_alert_service)


def _sessions(request: Request) -> sessionmaker[Session]:
    return cast(sessionmaker[Session], request.app.state.incident_session_factory)


def _tenant_id(request: Request) -> UUID:
    return cast(UUID, request.app.state.rag_demo_tenant_id)


def _operations_agent(request: Request) -> SecurityOperationsReportAgent:
    return cast(SecurityOperationsReportAgent, request.app.state.security_operations_report_agent)


def _authorized(request: Request, token: str | None) -> None:
    configured = _settings(request).wazuh_webhook_token.get_secret_value()
    if not configured:
        raise ApiError("wazuh_ingestion_unconfigured", "Wazuh ingestion is not configured", 503)
    if token is None or not hmac.compare_digest(token, configured):
        raise ApiError("wazuh_ingestion_unauthorized", "Wazuh webhook token is invalid", 401)


@router.post("/alerts", status_code=status.HTTP_202_ACCEPTED, response_model=WazuhAlertView)
def ingest_alert(
    payload: WazuhAlertInput,
    request: Request,
    x_shieldchain_wazuh_token: str | None = Header(default=None),
) -> WazuhAlertView:
    """Accept normalized evidence and optionally open a review-only case.

    This endpoint never launches an investigation runner or a trusted tool.
    """
    _authorized(request, x_shieldchain_wazuh_token)
    with _sessions(request).begin() as session:
        return _service(request).ingest(
            session,
            payload,
            tenant_id=_tenant_id(request),
            now=datetime.now(UTC),
            review_min_severity=_settings(request).wazuh_review_min_severity,
            review_correlation_window_seconds=_settings(
                request
            ).wazuh_review_correlation_window_seconds,
        )


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
        return WazuhReviewCaseListResponse(
            items=_service(request).list_review_cases(
                session,
                tenant_id=_tenant_id(request),
                limit=limit,
                correlation_window_seconds=_settings(
                    request
                ).wazuh_review_correlation_window_seconds,
            )
        )


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
    """Start agents only after an explicit operator action; ingestion stays passive."""

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
