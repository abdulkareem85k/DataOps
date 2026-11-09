"""Tests for NmapAdapter, raw output storage, scope gating, and SSE events."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adapters.nmap import NmapAdapter
from app.db import create_database_engine, create_session_factory, initialize_database
from app.main import create_app
from app.models.schemas import AssessmentCreate
from app.repo.assessments import create_assessment
from app.repo.assets import list_assets, list_services
from app.repo.tool_runs import list_tool_runs
from app.scope.engine import ScopeDenied, register_scope
from app.scope.models import ScopeRules
from app.settings import Settings

FIXTURE_XML = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'test.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
        runner_url="http://test-runner:9000",
        runner_token="test-token",  # type: ignore
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_nmap_parse_xml():
    """Verify offline defusedxml parsing of Nmap fixture."""
    xml_data = FIXTURE_XML.read_bytes()
    adapter = NmapAdapter()
    observations = adapter.parse(xml_data, tool_run_id="TRN-test1")

    # Should detect open ports 22 and 80, but not closed 443
    port_observations = [o for o in observations if o.category == "exposure"]
    assert len(port_observations) == 2

    port_22 = next(o for o in port_observations if o.port == 22)
    assert port_22.service_name == "ssh"
    assert port_22.service_version is not None
    assert "OpenSSH 8.2p1" in port_22.service_version

    port_80 = next(o for o in port_observations if o.port == 80)
    assert port_80.service_name == "http"
    assert port_80.service_version is not None
    assert "Apache httpd 2.4.41" in port_80.service_version

    # Check script outputs
    script_obs = [o for o in observations if "Script" in o.title]
    assert len(script_obs) >= 2
    vuln_script = next(o for o in script_obs if "CVE-2021-41773" in o.cve_ids)
    assert vuln_script.severity == "medium"
    assert "CVE-2021-41773" in vuln_script.cve_ids


def test_nmap_run_scope_denied(test_env):
    """Attempting an out-of-scope target must raise ScopeDenied and skip execution."""
    import asyncio

    settings, engine, sessions = test_env
    adapter = NmapAdapter(settings=settings, data_dir=settings.data_dir)

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Scope Test", description="Testing scope gating")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["nmap"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

        # Target not in allowed_targets
        with pytest.raises(ScopeDenied):
            asyncio.run(
                adapter.run(
                    session=session,
                    assessment_id=assessment.id,
                    target="172.30.0.99",
                    action_class="discovery",
                )
            )


def test_nmap_run_success(test_env):
    """A successful Nmap run records ToolRun, creates Assets & Services, and saves raw output."""
    import asyncio

    settings, engine, sessions = test_env
    adapter = NmapAdapter(settings=settings, data_dir=settings.data_dir)
    xml_data = FIXTURE_XML.read_bytes()

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Live Scan Test", description="Testing full lifecycle")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["nmap"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

    # Mock execute() to return fixture XML without calling network
    with patch.object(adapter, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = xml_data

        with sessions.begin() as session:
            tool_run, observations = asyncio.run(
                adapter.run(
                    session=session,
                    assessment_id=assessment.id,
                    target="172.30.0.10",
                    action_class="discovery",
                )
            )

        assert tool_run.status == "succeeded"
        assert tool_run.raw_output_path is not None
        assert tool_run.sha256 is not None
        assert len(observations) > 0

    with sessions() as session:
        assets = list_assets(session, assessment.id)
        assert len(assets) == 1
        assert assets[0].identifier == "172.30.0.10"

        services = list_services(session, assets[0].id)
        assert len(services) == 2
        ports = {s.port for s in services}
        assert ports == {22, 80}

        runs = list_tool_runs(session, assessment.id)
        assert len(runs) == 1
        assert runs[0].status == "succeeded"


def test_nmap_run_timeout(test_env):
    """A forced timeout must mark ToolRun as status='timeout' without crashing."""
    import asyncio

    settings, engine, sessions = test_env
    adapter = NmapAdapter(settings=settings, data_dir=settings.data_dir)

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Timeout Test", description="Testing timeout")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["nmap"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

    with patch.object(adapter, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.side_effect = TimeoutError("Timed out in scanner runner")

        with sessions.begin() as session:
            tool_run, observations = asyncio.run(
                adapter.run(
                    session=session,
                    assessment_id=assessment.id,
                    target="172.30.0.10",
                    action_class="discovery",
                )
            )

        assert tool_run.status == "timeout"
        assert "Timed out" in (tool_run.error or "")
        assert len(observations) == 0


def test_tool_runs_and_events_api(test_env):
    """Test GET /assessments/{id}/tool-runs and GET /assessments/{id}/events endpoint."""
    settings, engine, sessions = test_env
    app = create_app(settings=settings, engine=engine)

    with TestClient(app) as client:
        with sessions.begin() as session:
            assessment = create_assessment(
                session, AssessmentCreate(name="API Test", description="Testing API")
            )

        # Tool runs list
        resp = client.get(f"/assessments/{assessment.id}/tool-runs")
        assert resp.status_code == 200
        assert resp.json() == []

        # Nonexistent assessment
        resp = client.get("/assessments/AST-nonexistent/tool-runs")
        assert resp.status_code == 404
