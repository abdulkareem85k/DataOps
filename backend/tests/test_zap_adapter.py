"""Tests for ZapAdapter, active-scan gate, parsing, and scope gating."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.zap import ZapAdapter
from app.db import create_database_engine, create_session_factory, initialize_database
from app.models.schemas import AssessmentCreate
from app.repo.assessments import create_assessment
from app.repo.tool_runs import list_tool_runs
from app.scope.enforcement import ScopeToken
from app.scope.engine import ScopeDenied, register_scope
from app.scope.models import Decision, ScopeRules
from app.settings import Settings

FIXTURE_JSON = Path(__file__).parent / "fixtures" / "zap_sample.json"


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'zap.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
        zap_url="http://test-zap:8090",
        zap_api_key="zap-secret",  # type: ignore
        enable_zap_active_scan=False,  # Gated by default!
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_zap_parse_alerts():
    """Verify offline parsing of ZAP JSON alert fixtures."""
    raw_data = FIXTURE_JSON.read_bytes()
    adapter = ZapAdapter()
    observations = adapter.parse(raw_data, tool_run_id="TRN-zap1")

    assert len(observations) == 2

    # High severity XSS finding
    xss_obs = next(o for o in observations if "XSS" in o.title or "Cross Site Scripting" in o.title)
    assert xss_obs.severity == "high"
    assert xss_obs.confidence == "high"
    assert xss_obs.confidence_score == 0.9
    assert xss_obs.category == "owasp_top10"
    assert "CWE-79" in xss_obs.cwe_ids
    assert xss_obs.parameter == "q"
    assert "<script>" in xss_obs.evidence

    # Low severity CSP finding
    csp_obs = next(o for o in observations if "CSP" in o.title or "Policy" in o.title)
    assert csp_obs.severity == "low"
    assert csp_obs.confidence == "medium"
    assert csp_obs.category == "misconfig"
    assert "CWE-16" in csp_obs.cwe_ids


def test_zap_active_scan_gate_rejects_by_default(test_env):
    """Attempting active scan when ENABLE_ZAP_ACTIVE_SCAN=false must raise PermissionError."""
    settings, engine, sessions = test_env
    assert settings.enable_zap_active_scan is False

    adapter = ZapAdapter(settings=settings, data_dir=settings.data_dir)
    token = ScopeToken(
        assessment_id="ASM-test",
        tool="zap",
        target="172.30.0.10",
        decision=Decision.allow("test"),
        _marker="require_scope:v1",
    )

    with pytest.raises(PermissionError) as exc_info:
        asyncio.run(
            adapter.execute(
                target="http://172.30.0.10",
                args={"active_scan": True},
                token=token,
            )
        )
    assert "ENABLE_ZAP_ACTIVE_SCAN=false" in str(exc_info.value)


def test_zap_run_scope_denied(test_env):
    """ZAP run with out-of-scope target must be denied before hitting ZAP."""
    settings, engine, sessions = test_env
    adapter = ZapAdapter(settings=settings, data_dir=settings.data_dir)

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="ZAP Scope", description="Testing scope")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["zap"],
                allowed_action_classes=["web_scan"],
            ),
            settings=settings,
        )

        with pytest.raises(ScopeDenied):
            asyncio.run(
                adapter.run(
                    session=session,
                    assessment_id=assessment.id,
                    target="http://172.30.0.99",
                    action_class="web_scan",
                )
            )


def test_zap_run_passive_success(test_env):
    """A passive scan run succeeds, creates ToolRun and parses findings."""
    settings, engine, sessions = test_env
    adapter = ZapAdapter(settings=settings, data_dir=settings.data_dir)
    raw_data = FIXTURE_JSON.read_bytes()

    with sessions.begin() as session:
        assessment = create_assessment(
            session,
            AssessmentCreate(name="ZAP Passive Scan", description="Testing live passive scan"),
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["zap"],
                allowed_action_classes=["web_scan"],
            ),
            settings=settings,
        )

    with patch.object(adapter, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = raw_data

        with sessions.begin() as session:
            tool_run, observations = asyncio.run(
                adapter.run(
                    session=session,
                    assessment_id=assessment.id,
                    target="172.30.0.10",
                    action_class="web_scan",
                )
            )

        assert tool_run.status == "succeeded"
        assert tool_run.raw_output_path is not None
        assert len(observations) == 2

    with sessions() as session:
        runs = list_tool_runs(session, assessment.id)
        assert len(runs) == 1
        assert runs[0].tool == "zap"
        assert runs[0].status == "succeeded"
