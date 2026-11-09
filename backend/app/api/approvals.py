"""Human-in-the-loop approval management HTTP endpoints."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.approvals.service import decide_approval, list_approvals
from app.db import get_session
from app.repo.assessments import get_assessment
from app.repo.common import RecordNotFound

router = APIRouter()
DbSession = Annotated[Session, Depends(get_session)]


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(default="", max_length=2000)
    approver: str = Field(default="security-analyst", max_length=160)


@router.get("/assessments/{assessment_id}/approvals")
def get_approvals_endpoint(
    assessment_id: str,
    session: DbSession,
) -> list[dict[str, Any]]:
    """List pending and decided approval requests for an assessment."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    return list_approvals(session, assessment_id)


@router.post("/approvals/{approval_id}/decision")
def record_decision_endpoint(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    session: DbSession,
) -> dict[str, Any]:
    """Record authorized human approval or rejection for a validation action."""
    try:
        updated = decide_approval(
            session=session,
            approval_id=approval_id,
            decision=payload.decision,
            reason=payload.reason,
            approver_user=payload.approver,
        )
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "approval_id": updated.id,
        "status": updated.status,
        "decided_at": str(updated.decided_at),
        "reason": updated.reason,
    }
