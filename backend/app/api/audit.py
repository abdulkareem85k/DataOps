"""API endpoints for exploring, verifying, and exporting the audit trail."""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_session
from app.models.schemas import AuditEventRead
from app.repo import RecordNotFound, list_audit_events, verify_chain

audit_router = APIRouter(tags=["Audit"])
DbSession = Annotated[Session, Depends(get_session)]


class AuditVerifyResponse(BaseModel):
    assessment_id: str
    verified: bool
    event_count: int
    message: str


@audit_router.get(
    "/assessments/{assessment_id}/audit",
    response_model=list[AuditEventRead],
)
def get_assessment_audit_events(
    assessment_id: str,
    session: DbSession,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AuditEventRead]:
    """Retrieve the cryptographically chained audit events for an assessment."""
    try:
        events = list_audit_events(session, assessment_id)
        return events[skip : skip + limit]
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@audit_router.get(
    "/assessments/{assessment_id}/audit/verify",
    response_model=AuditVerifyResponse,
)
def verify_assessment_audit_chain(
    assessment_id: str,
    session: DbSession,
) -> AuditVerifyResponse:
    """Verify cryptographic SHA-256 chain integrity from genesis for an assessment."""
    try:
        events = list_audit_events(session, assessment_id)
        is_valid = verify_chain(session, assessment_id)
        msg = (
            "Cryptographic SHA-256 hash chain is verified intact from genesis."
            if is_valid
            else "Tamper detected: audit hash chain sequence or hash mismatch."
        )
        return AuditVerifyResponse(
            assessment_id=assessment_id,
            verified=is_valid,
            event_count=len(events),
            message=msg,
        )
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@audit_router.get(
    "/assessments/{assessment_id}/audit/export",
    response_class=Response,
)
def export_assessment_audit(
    assessment_id: str,
    session: DbSession,
    format: str = Query(default="json", pattern="^(json|csv)$"),
) -> Response:
    """Export the complete audit chain as canonical JSON or CSV."""
    try:
        events = list_audit_events(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(
            [
                "seq",
                "id",
                "timestamp",
                "actor",
                "event_type",
                "outcome",
                "hash",
                "prev_hash",
                "detail",
            ]
        )
        for ev in events:
            writer.writerow(
                [
                    ev.seq,
                    ev.id,
                    ev.timestamp.isoformat(),
                    ev.actor,
                    ev.event_type,
                    ev.outcome,
                    ev.hash,
                    ev.prev_hash,
                    json.dumps(ev.detail),
                ]
            )
        return Response(
            content=out.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="audit_{assessment_id}.csv"'},
        )

    # JSON export
    raw_list = [ev.model_dump(mode="json") for ev in events]
    return Response(
        content=json.dumps(raw_list, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="audit_{assessment_id}.json"'},
    )
