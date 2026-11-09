"""Assessment and scope HTTP endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_session
from app.models.schemas import (
    AssessmentCreate,
    AssessmentRead,
    ScopeCheckRequest,
    ScopeRuleCreate,
    ScopeRuleRead,
)
from app.repo.assessments import create_assessment, get_assessment, list_assessments
from app.repo.common import RecordNotFound
from app.repo.scope import get_scope_rules
from app.scope.engine import ScopeRegistrationError, check_action, register_scope
from app.scope.models import Decision, ScopeRules
from app.settings import Settings, get_settings

router = APIRouter()


def _settings(request: Request) -> Settings:
    return getattr(request.app.state, "settings", None) or get_settings()


DbSession = Annotated[Session, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(_settings)]


@router.get("/assessments", response_model=list[AssessmentRead])
def list_assessments_endpoint(
    session: DbSession,
) -> list[AssessmentRead]:
    """List all assessments ordered chronologically descending."""
    return list_assessments(session)


@router.post("/assessments", response_model=AssessmentRead)
def create_assessment_endpoint(
    payload: AssessmentCreate,
    session: DbSession,
) -> AssessmentRead:
    """Create an assessment workspace."""
    return create_assessment(session, payload)


@router.post("/assessments/{assessment_id}/scope", response_model=ScopeRuleRead)
def register_scope_endpoint(
    assessment_id: str,
    payload: ScopeRuleCreate,
    session: DbSession,
    settings: AppSettings,
) -> ScopeRuleRead:
    """Validate and store deterministic scope rules for an assessment."""
    try:
        get_assessment(session, assessment_id)
        return register_scope(
            session,
            assessment_id,
            ScopeRules.model_validate(payload.model_dump()),
            settings=settings,
        )
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ScopeRegistrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assessments/{assessment_id}/scope", response_model=ScopeRuleRead)
def get_scope_endpoint(
    assessment_id: str,
    session: DbSession,
) -> ScopeRuleRead:
    """Return the stored scope document."""
    try:
        return get_scope_rules(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/assessments/{assessment_id}/scope/check", response_model=Decision)
def check_scope_endpoint(
    assessment_id: str,
    payload: ScopeCheckRequest,
    session: DbSession,
    settings: AppSettings,
) -> Decision:
    """Evaluate a proposed tool action against stored scope (no execution)."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return check_action(
        session,
        assessment_id,
        payload.tool,
        payload.target,
        payload.action_class,
        payload.args,
        settings=settings,
    )
