"""Tests for NiktoAdapter, parsing, scope enforcement, and runner interaction."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.nikto import NiktoAdapter
from app.db import create_database_engine, create_session_factory, initialize_database
from app.models.schemas import AssessmentCreate
from app.repo.assessments import create_assessment
from app.repo.tool_runs import list_tool_runs
from app.scope.engine import ScopeDenied, register_scope
from app.scope.models import ScopeRules
from app.settings import Settings

FIXTURE_JSON = Path(__file__).parent / "fixtures" / "nikto_sample.json"


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'nikto.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
        runner_url="http://test-runner:9000",
        runner_token="test-token",  # type: ignore
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_nikto_parse_json():
    """Verify offline parsing of recorded Nikto JSON output."""
    raw_data = FIXTURE_JSON.read_bytes()
    adapter = NiktoAdapter()
    observations = adapter.parse(raw_data, tool_run_id="TRN-nikto1")

    assert len(observations) == 4  # 1 banner + 3 vulnerabilities

    # Banner check
    banner_obs = next(o for o in observations if "Banner" in o.title)
    assert banner_obs.service_version == "Apache/2.4.41 (Ubuntu)"
    assert banner_obs.severity == "info"

    # CVE extraction check
    cve_obs = next(o for o in observations if "CVE-2020-0001" in o.cve_ids)
    assert "CVE-2020-0001" in cve_obs.cve_ids
    assert cve_obs.category == "outdated_software"

    # OSVDB check
    osvdb_obs = next(o for o in observations if any("3092" in r for r in o.references))
    assert osvdb_obs.url == "/test/"
    assert osvdb_obs.severity == "medium"


def test_nikto_run_scope_denied(test_env):
    """Out-of-scope targets must be rejected before calling runner."""
    settings, engine, sessions = test_env
    adapter = NiktoAdapter(settings=settings, data_dir=settings.data_dir)

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Nikto Scope", description="Testing scope")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["nikto"],
                allowed_action_classes=["web_scan"],
            ),
            settings=settings,
        )

        with pytest.raises(ScopeDenied):
            asyncio.run(
                adapter.run(
                    session=session,
                    assessment_id=assessment.id,
                    target="172.30.0.99",
                    action_class="web_scan",
                )
            )


def test_nikto_run_success(test_env):
    """Successful run persists raw output, creates tool run, and returns observations."""
    settings, engine, sessions = test_env
    adapter = NiktoAdapter(settings=settings, data_dir=settings.data_dir)
    raw_data = FIXTURE_JSON.read_bytes()

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Nikto Scan", description="Testing live run")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["nikto"],
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
        assert tool_run.sha256 is not None
        assert len(observations) == 4

    with sessions() as session:
        runs = list_tool_runs(session, assessment.id)
        assert len(runs) == 1
        assert runs[0].tool == "nikto"
        assert runs[0].status == "succeeded"
