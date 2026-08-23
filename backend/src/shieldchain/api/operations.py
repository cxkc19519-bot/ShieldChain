from __future__ import annotations

from typing import cast

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from shieldchain.operations.schemas import (
    OperationsReportListResponse,
    OperationsReportRequest,
    OperationsReportView,
)
from shieldchain.operations.service import SecurityOperationsReportAgent

router = APIRouter(prefix="/operations/reports", tags=["operations"])


def _agent(request: Request) -> SecurityOperationsReportAgent:
    return cast(SecurityOperationsReportAgent, request.app.state.security_operations_report_agent)


@router.post("", response_model=OperationsReportView, status_code=status.HTTP_201_CREATED)
async def create_report(payload: OperationsReportRequest, request: Request) -> OperationsReportView:
    try:
        return await _agent(request).generate(payload, request_id=str(request.state.request_id))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None


@router.get("", response_model=OperationsReportListResponse)
def list_reports(request: Request, limit: int = Query(default=30, ge=1, le=100)) -> OperationsReportListResponse:
    return OperationsReportListResponse(items=_agent(request).list(limit))


@router.get("/{report_id}", response_model=OperationsReportView)
def get_report(report_id: str, request: Request) -> OperationsReportView:
    report = _agent(request).get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="运营报告不存在")
    return report


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    format: str = Query(default="markdown", pattern="^(markdown|html)$"),
) -> Response:
    report = _agent(request).get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="运营报告不存在")
    if format == "html":
        return Response(
            content=report.html,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{report.id}.html"'},
        )
    return Response(
        content=report.markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{report.id}.md"'},
    )
