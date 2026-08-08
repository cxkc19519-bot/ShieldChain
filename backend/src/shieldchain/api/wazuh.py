from __future__ import annotations

import hmac
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request, status
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.wazuh.schemas import (
    WazuhAlertInput,
    WazuhAlertListResponse,
    WazuhAlertView,
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
