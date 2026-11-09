"""Tests for human approval workflow, single-use token verification, TTL, and Metasploit adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.metasploit import MetasploitAdapter
from app.approvals.service import (
    create_approval_request,
    decide_approval,
    verify_approval_token,
)
from app.db import create_database_engine, create_session_factory, initialize_database
from app.main import create_app
from app.models.schemas import (
    AssessmentCreate,
)
from app.repo.assessments import create_assessment
from app.scope.engine import ScopeDenied, register_scope
from app.scope.models import ScopeRules
from app.settings import Settings

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'approvals.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
        enable_active_validation=True,  # enabled for approval testing
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_unapproved_validation_rejected(test_env):
    """Validation attempted without human approval must be rejected."""
    settings, engine, sessions = test_env
    adapter = MetasploitAdapter(settings=settings, data_dir=settings.data_dir)

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Unapproved Test"))

        # Non-existent approval ID
        with pytest.raises(PermissionError) as exc_info:
            asyncio.run(
                adapter.run_validation(
                    session=session,
                    assessment_id=assessment.id,
                    finding_id="FND-0001",
                    target="172.30.0.10",
                    approval_id="APR-nonexistent",
                )
            )
        assert "not found" in str(exc_info.value).lower()


def test_modifying_parameters_invalidates_approval(test_env):
    """Any change to tool, target, or parameters invalidates the approval token."""
    settings, engine, sessions = test_env

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Param Invalidation Test"))
        appr = create_approval_request(
            session=session,
            assessment_id=assessment.id,
            finding_id="FND-0001",
            tool="metasploit",
            target="172.30.0.10",
            params={"module": "auxiliary/check_vuln", "port": 80},
        )
        decide_approval(session, appr.id, "approve", reason="Approved for port 80")

        # Modifying target address
        with pytest.raises(PermissionError) as exc1:
            verify_approval_token(
                session,
                appr.id,
                expected_tool="metasploit",
                expected_target="172.30.0.99",  # Modified!
                expected_params={"module": "auxiliary/check_vuln", "port": 80},
            )
        assert "target" in str(exc1.value)

        # Modifying params
        with pytest.raises(PermissionError) as exc2:
            verify_approval_token(
                session,
                appr.id,
                expected_tool="metasploit",
                expected_target="172.30.0.10",
                expected_params={"module": "auxiliary/check_vuln", "port": 443},  # Modified port!
            )
        assert "parameters do not match" in str(exc2.value)


def test_expired_approval_rejected(test_env):
    """An approval past its 15-minute TTL must be rejected as expired."""
    settings, engine, sessions = test_env

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="TTL Expiry Test"))
        appr = create_approval_request(
            session=session,
            assessment_id=assessment.id,
            finding_id="FND-0001",
            tool="metasploit",
            target="172.30.0.10",
        )
        decide_approval(session, appr.id, "approve")

        # Manually backdate decided_at by 20 minutes
        appr.decided_at = datetime.now(UTC) - timedelta(minutes=20)
        session.flush()

        with pytest.raises(PermissionError) as exc:
            verify_approval_token(
                session,
                appr.id,
                expected_tool="metasploit",
                expected_target="172.30.0.10",
            )
        assert "expired" in str(exc.value).lower()


def test_out_of_scope_target_blocked_even_if_approved(test_env):
    """Scope check is revalidated at execution time; approved action on
    out-of-scope target fails.
    """
    settings, engine, sessions = test_env
    adapter = MetasploitAdapter(settings=settings, data_dir=settings.data_dir)

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Scope Override Test"))
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],  # 172.30.0.99 is NOT in scope
                allowed_tools=["metasploit"],
                allowed_action_classes=["active_validation"],
            ),
            settings=settings,
        )

        appr = create_approval_request(
            session=session,
            assessment_id=assessment.id,
            finding_id="FND-0001",
            tool="metasploit",
            target="172.30.0.99",
        )
        decide_approval(session, appr.id, "approve")

        with pytest.raises(ScopeDenied):
            asyncio.run(
                adapter.run_validation(
                    session=session,
                    assessment_id=assessment.id,
                    finding_id="FND-0001",
                    target="172.30.0.99",
                    approval_id=appr.id,
                )
            )


def test_single_use_approval_cannot_be_replayed(test_env):
    """An approved token is consumed upon first use and cannot be reused."""
    settings, engine, sessions = test_env

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Single Use Test"))
        appr = create_approval_request(
            session=session,
            assessment_id=assessment.id,
            finding_id="FND-0001",
            tool="metasploit",
            target="172.30.0.10",
        )
        decide_approval(session, appr.id, "approve")

        # First verification succeeds and consumes token
        data = verify_approval_token(
            session,
            appr.id,
            expected_tool="metasploit",
            expected_target="172.30.0.10",
        )
        assert data["target"] == "172.30.0.10"

        # Replay attempt must fail!
        with pytest.raises(PermissionError) as exc:
            verify_approval_token(
                session,
                appr.id,
                expected_tool="metasploit",
                expected_target="172.30.0.10",
            )
        assert "consumed" in str(exc.value).lower()


def test_approvals_api_workflow(test_env):
    """Test GET /assessments/{id}/approvals and POST /approvals/{id}/decision."""
    settings, engine, sessions = test_env
    app = create_app(settings=settings, engine=engine)

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="API Approvals Test"))
        appr = create_approval_request(
            session=session,
            assessment_id=assessment.id,
            finding_id="FND-0001",
            tool="metasploit",
            target="172.30.0.10",
            justification="Confirm RCE",
        )

    with TestClient(app) as client:
        # List pending
        resp = client.get(f"/assessments/{assessment.id}/approvals")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["status"] == "pending"

        # Record approval decision
        dec_resp = client.post(
            f"/approvals/{appr.id}/decision",
            json={
                "decision": "approve",
                "reason": "Authorized by lead",
                "approver": "lead-analyst",
            },
        )
        assert dec_resp.status_code == 200
        assert dec_resp.json()["status"] == "approved"
