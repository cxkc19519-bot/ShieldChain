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


def _html_response(
    report: OperationsReportView,
    request: Request,
    *,
    disposition: str,
) -> Response:
    """Serve one canonical HTML rendering for both viewing and downloading."""

    return Response(
        content=_agent(request).standalone_html(report),
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'{disposition}; filename="{report.id}.html"',
            "Cache-Control": "no-store, max-age=0",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                "base-uri 'none'; frame-ancestors 'self'"
            ),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.post("", response_model=OperationsReportView, status_code=status.HTTP_201_CREATED)
async def create_report(payload: OperationsReportRequest, request: Request) -> OperationsReportView:
    try:
        return await _agent(request).generate(payload, request_id=str(request.state.request_id))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None


@router.get("", response_model=OperationsReportListResponse)
def list_reports(
    request: Request, limit: int = Query(default=30, ge=1, le=100)
) -> OperationsReportListResponse:
    return OperationsReportListResponse(items=_agent(request).list(limit))


@router.get("/{report_id}", response_model=OperationsReportView)
def get_report(report_id: str, request: Request) -> OperationsReportView:
    report = _agent(request).get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="运营报告不存在")
    return report


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(report_id: str, request: Request) -> Response:
    if not _agent(request).delete(report_id):
        raise HTTPException(status_code=404, detail="运营报告不存在")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
        return _html_response(report, request, disposition="attachment")
    return Response(
        content=report.markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{report.id}.md"'},
    )


@router.get("/{report_id}/view")
def view_report(
    report_id: str,
    request: Request,
    download: bool = Query(default=False),
) -> Response:
    """Render one immutable report as a standalone, script-free HTML document."""

    report = _agent(request).get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="运营报告不存在")
    return _html_response(
        report,
        request,
        disposition="attachment" if download else "inline",
    )
