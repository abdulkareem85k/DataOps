"""Human approval workflow service with single-use 15-minute token verification."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.orm import Approval
from app.repo.audit import append_audit_event
from app.repo.common import RecordNotFound, as_utc, new_id

APPROVAL_TTL_SECONDS = 15 * 60  # 15 minutes TTL


def utc_now() -> datetime:
    return datetime.now(UTC)


def create_approval_request(
    session: Session,
    assessment_id: str,
    finding_id: str,
    tool: str,
    target: str,
    params: dict[str, Any] | None = None,
    justification: str = "",
    risk: str = "",
) -> Approval:
    """Create a pending human approval request for an intrusive or active validation action."""
    action_data = {
        "finding_id": finding_id,
        "tool": tool,
        "target": target,
        "params": params or {},
        "justification": justification,
        "risk": risk,
    }

    row = Approval(
        id=new_id("APR"),
        assessment_id=assessment_id,
        action=json.dumps(action_data, sort_keys=True),
        requested_by="ai-agent",
        status="pending",
        reason=None,
    )
    session.add(row)
    session.flush()

    append_audit_event(
        session,
        assessment_id=assessment_id,
        actor="agent",
        event_type="approval.requested",
        detail={
            "approval_id": row.id,
            "finding_id": finding_id,
            "tool": tool,
            "target": target,
            "params": params or {},
            "justification": justification,
            "risk": risk,
        },
        outcome="pending",
    )
    return row


def decide_approval(
    session: Session,
    approval_id: str,
    decision: Literal["approve", "reject"],
    reason: str = "",
    approver_user: str = "security-analyst",
) -> Approval:
    """Record a human decision (approve/reject) for a pending request."""
    row = session.get(Approval, approval_id)
    if row is None:
        raise RecordNotFound("approval request not found")
    if row.status != "pending":
        raise ValueError(f"Approval request cannot be decided; current status is '{row.status}'")

    now = utc_now()
    row.status = "approved" if decision == "approve" else "rejected"
    row.decided_at = now
    row.reason = (
        f"Decided by {approver_user}: {reason}" if reason else f"Decided by {approver_user}"
    )
    session.flush()

    append_audit_event(
        session,
        assessment_id=row.assessment_id,
        actor="user",
        event_type=f"approval.{decision}",
        detail={
            "approval_id": row.id,
            "decision": decision,
            "reason": reason,
            "approver": approver_user,
        },
        outcome=decision,
    )
    return row


def verify_approval_token(
    session: Session,
    approval_id: str,
    expected_tool: str,
    expected_target: str,
    expected_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify approval token validity, 15-minute TTL, single-use, and parameter matching."""
    row = session.get(Approval, approval_id)
    if row is None:
        raise PermissionError("Approval record not found.")

    if row.status == "consumed":
        raise PermissionError("Approval token has already been consumed (single-use token).")

    if row.status != "approved":
        raise PermissionError(
            f"Action requires approved human authorization; current status is '{row.status}'."
        )

    # Time-bound check (15 minutes TTL)
    if row.decided_at is None:
        raise PermissionError("Approval has no decision timestamp.")

    age_seconds = (utc_now() - as_utc(row.decided_at)).total_seconds()
    if age_seconds > APPROVAL_TTL_SECONDS:
        row.status = "expired"
        session.flush()
        raise PermissionError(
            f"Approval token has expired (TTL {APPROVAL_TTL_SECONDS // 60} minutes exceeded)."
        )

    # Parameter and target matching check
    try:
        action_data = json.loads(row.action)
    except Exception as exc:
        raise PermissionError("Approval payload is corrupted.") from exc

    if action_data.get("tool") != expected_tool:
        raise PermissionError(
            f"Approval invalidated: approved tool '{action_data.get('tool')}' "
            f"does not match requested '{expected_tool}'."
        )

    if action_data.get("target") != expected_target:
        raise PermissionError(
            f"Approval invalidated: approved target '{action_data.get('target')}' "
            f"does not match requested '{expected_target}'."
        )

    if expected_params is not None:
        approved_params = action_data.get("params") or {}
        if approved_params != expected_params:
            raise PermissionError("Approval invalidated: parameters do not match approved request.")

    # Consume single-use token immediately
    row.status = "consumed"
    session.flush()

    append_audit_event(
        session,
        assessment_id=row.assessment_id,
        actor="agent",
        event_type="approval.consumed",
        detail={"approval_id": row.id, "tool": expected_tool, "target": expected_target},
        outcome="consumed",
    )
    return action_data


def list_approvals(session: Session, assessment_id: str) -> list[dict[str, Any]]:
    """List all approval requests for an assessment."""
    rows = (
        session.execute(
            select(Approval)
            .where(Approval.assessment_id == assessment_id)
            .order_by(Approval.created_at.desc())
        )
        .scalars()
        .all()
    )
    result = []
    for r in rows:
        try:
            payload = json.loads(r.action)
        except Exception:
            payload = {"raw_action": r.action}
        result.append(
            {
                "id": r.id,
                "assessment_id": r.assessment_id,
                "status": r.status,
                "requested_by": r.requested_by,
                "reason": r.reason,
                "created_at": str(r.created_at),
                "decided_at": str(r.decided_at) if r.decided_at else None,
                "payload": payload,
            }
        )
    return result
