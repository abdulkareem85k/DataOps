"""Multipart report file import HTTP endpoint."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.db import get_session
from app.importers.burp import BurpImporter
from app.importers.nessus import NessusImporter
from app.importers.openvas import OpenVasImporter
from app.repo.assessments import get_assessment
from app.repo.common import RecordNotFound
from app.settings import Settings, get_settings

router = APIRouter()
DbSession = Annotated[Session, Depends(get_session)]


def _get_settings(request: Request) -> Settings:
    return getattr(request.app.state, "settings", None) or get_settings()


@router.post("/assessments/{assessment_id}/imports")
async def import_report_endpoint(
    assessment_id: str,
    file: Annotated[UploadFile, File()],
    session: DbSession = None,  # type: ignore
    request: Request = None,  # type: ignore
) -> dict[str, Any]:
    """Upload commercial scanner report (.nessus, .xml) for secure offline import."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    filename = file.filename or "unknown.xml"
    content = await file.read()

    settings = _get_settings(request)
    lower_fn = filename.lower()
    snippet = content[:2000].decode("utf-8", errors="ignore").lower()

    if lower_fn.endswith(".nessus") or "nessusclientdata" in snippet:
        importer = NessusImporter(settings=settings)
    elif "<issues" in snippet or "burp" in snippet:
        importer = BurpImporter(settings=settings)
    elif "<report" in snippet or "openvas" in snippet or "greenbone" in snippet:
        importer = OpenVasImporter(settings=settings)
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported report format. Only .nessus, OpenVAS XML, "
                "and Burp Suite XML are supported."
            ),
        )

    try:
        tool_run, observations, skipped_hosts = importer.import_file(
            session=session,
            assessment_id=assessment_id,
            filename=filename,
            content=content,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"File import failed: {exc}") from exc

    return {
        "tool_run": tool_run,
        "observations_count": len(observations),
        "skipped_hosts": skipped_hosts,
    }
