"""Scope-rule persistence via the repository layer."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.orm import Assessment, ScopeRule
from app.models.schemas import ScopeRuleCreate, ScopeRuleRead
from app.repo.common import RecordNotFound, as_utc, new_id


def upsert_scope_rules(
    session: Session, assessment_id: str, payload: ScopeRuleCreate
) -> ScopeRuleRead:
    """Replace the stored scope document for an assessment."""
    if session.get(Assessment, assessment_id) is None:
        raise RecordNotFound("assessment not found")
    row = session.scalar(select(ScopeRule).where(ScopeRule.assessment_id == assessment_id))
    if row is None:
        row = ScopeRule(id=new_id("SCR"), assessment_id=assessment_id)
        session.add(row)
    row.allowed_targets = list(payload.allowed_targets)
    row.exclusions = list(payload.exclusions)
    row.allowed_tools = list(payload.allowed_tools)
    row.allowed_action_classes = list(payload.allowed_action_classes)
    row.rate_limit_max = payload.rate_limit_max
    row.rate_limit_window_seconds = payload.rate_limit_window_seconds
    row.window_start = payload.window_start
    row.window_end = payload.window_end
    row.notes = payload.notes
    session.flush()
    return to_scope_read(row)


def get_scope_rules(session: Session, assessment_id: str) -> ScopeRuleRead:
    """Read the stored scope document or raise RecordNotFound."""
    if session.get(Assessment, assessment_id) is None:
        raise RecordNotFound("assessment not found")
    row = session.scalar(select(ScopeRule).where(ScopeRule.assessment_id == assessment_id))
    if row is None:
        raise RecordNotFound("scope is not registered")
    return to_scope_read(row)


def to_scope_read(row: ScopeRule) -> ScopeRuleRead:
    """Map a ScopeRule ORM row to the public read schema."""
    return ScopeRuleRead(
        id=row.id,
        assessment_id=row.assessment_id,
        allowed_targets=list(row.allowed_targets or []),
        exclusions=list(row.exclusions or []),
        allowed_tools=list(row.allowed_tools or []),
        allowed_action_classes=list(row.allowed_action_classes or []),
        rate_limit_max=row.rate_limit_max,
        rate_limit_window_seconds=row.rate_limit_window_seconds,
        window_start=as_utc(row.window_start) if row.window_start else None,
        window_end=as_utc(row.window_end) if row.window_end else None,
        notes=row.notes,
        created_at=as_utc(row.created_at),
    )
