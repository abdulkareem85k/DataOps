"""API routes for VAPT Report generation and preview."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_session
from app.repo import RecordNotFound
from app.reports.generator import (
    UngroundedReportError,
    generate_report_data,
    generate_report_pdf,
    render_report_html,
)

reports_router = APIRouter(tags=["Reports"])
DbSession = Annotated[Session, Depends(get_session)]


class GenerateReportRequest(BaseModel):
    executive_narrative: str | None = Field(
        default=None,
        description="Optional custom executive narrative to include in the generated report",
    )


class ReportMetadataResponse(BaseModel):
    assessment_id: str
    status: str
    generated_at: str
    total_findings: int
    risk_posture: str
    pdf_download_url: str
    html_preview_url: str
    audit_chain_verified: bool


@reports_router.post(
    "/assessments/{assessment_id}/report",
    response_model=ReportMetadataResponse,
)
def create_report(
    assessment_id: str,
    session: DbSession,
    payload: GenerateReportRequest | None = None,
) -> Any:
    """Generate and validate report data for an assessment."""
    narrative = payload.executive_narrative if payload else None
    try:
        data = generate_report_data(session, assessment_id, narrative)
        # Validate that generation succeeds
        _ = generate_report_pdf(session, assessment_id, narrative)
        return ReportMetadataResponse(
            assessment_id=assessment_id,
            status="generated",
            generated_at=data["generated_at"],
            total_findings=data["summary"]["total_findings"],
            risk_posture=data["summary"]["overall_posture"],
            pdf_download_url=f"/assessments/{assessment_id}/report.pdf",
            html_preview_url=f"/assessments/{assessment_id}/report/preview",
            audit_chain_verified=data["audit_verified"],
        )
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UngroundedReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report compilation failed: {exc}") from exc


@reports_router.get(
    "/assessments/{assessment_id}/report.pdf",
    response_class=Response,
)
def download_report_pdf(
    assessment_id: str,
    session: DbSession,
    narrative: str | None = Query(default=None),
) -> Response:
    """Download the client-ready VAPT assessment report as a styled PDF."""
    try:
        pdf_bytes = generate_report_pdf(session, assessment_id, narrative)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="VAPT_Report_{assessment_id}.pdf"'
            },
        )
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UngroundedReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc


@reports_router.get(
    "/assessments/{assessment_id}/report/preview",
    response_class=HTMLResponse,
)
def preview_report_html(
    assessment_id: str,
    session: DbSession,
    narrative: str | None = Query(default=None),
) -> HTMLResponse:
    """Render the live HTML preview of the VAPT report."""
    try:
        html_content = render_report_html(session, assessment_id, narrative)
        return HTMLResponse(content=html_content)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UngroundedReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"HTML preview generation failed: {exc}"
        ) from exc
