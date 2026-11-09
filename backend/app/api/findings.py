"""Findings and risk analytics HTTP endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_session
from app.models.schemas import FindingRead
from app.pipeline.risk import recalculate_assessment_risks
from app.repo.assessments import get_assessment
from app.repo.common import RecordNotFound
from app.repo.findings import get_finding, get_findings_summary, list_findings

router = APIRouter()
DbSession = Annotated[Session, Depends(get_session)]


@router.get("/assessments/{assessment_id}/findings", response_model=list[FindingRead])
def list_findings_endpoint(
    assessment_id: str,
    session: DbSession,
    sort: str = Query("risk", pattern="^(risk|severity|first_seen)$"),
    severity: str | None = None,
    status: str | None = None,
    asset_id: str | None = None,
    tool: str | None = None,
) -> list[FindingRead]:
    """Query assessment findings with sorting and multi-field filtering."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    return list_findings(
        session=session,
        assessment_id=assessment_id,
        sort=sort,
        severity=severity,
        status=status,
        asset_id=asset_id,
        tool=tool,
    )


@router.get("/assessments/{assessment_id}/findings/summary")
def get_findings_summary_endpoint(
    assessment_id: str,
    session: DbSession,
) -> dict[str, Any]:
    """Return aggregated severity, risk band, and status metrics for an assessment."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    return get_findings_summary(session, assessment_id)


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding_endpoint(
    finding_id: str,
    session: DbSession,
) -> FindingRead:
    """Read one security finding by its identifier."""
    try:
        return get_finding(session, finding_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc


@router.post("/assessments/{assessment_id}/findings/recalculate-risk")
def recalculate_risk_endpoint(
    assessment_id: str,
    session: DbSession,
) -> dict[str, Any]:
    """Recalculate risk scores for all findings in the assessment."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    updated = recalculate_assessment_risks(session, assessment_id)
    return {"updated_count": len(updated)}
