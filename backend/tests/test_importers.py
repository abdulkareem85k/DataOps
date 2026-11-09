"""Tests for Nessus, OpenVAS, and Burp Suite importers, XXE safety, and scope enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import create_database_engine, create_session_factory, initialize_database
from app.importers.burp import BurpImporter
from app.importers.nessus import NessusImporter
from app.importers.openvas import OpenVasImporter
from app.main import create_app
from app.models.schemas import AssessmentCreate
from app.repo.assessments import create_assessment
from app.repo.audit import list_audit_events
from app.scope.engine import register_scope
from app.scope.models import ScopeRules
from app.settings import Settings

SAMPLES_DIR = Path(__file__).parent.parent.parent / "lab" / "samples"


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'imports.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_nessus_importer_with_scope_skipping(test_env):
    """Nessus importer imports in-scope hosts and logs skipped out-of-scope hosts."""
    settings, engine, sessions = test_env
    importer = NessusImporter(settings=settings, data_dir=settings.data_dir)
    sample_file = SAMPLES_DIR / "sample.nessus"
    content = sample_file.read_bytes()

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Nessus Import Test", description="Testing Nessus")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],  # 192.168.1.50 is NOT in scope
                allowed_tools=["nessus"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

        tool_run, obs, skipped = importer.import_file(
            session, assessment.id, "sample.nessus", content
        )

    assert tool_run.mode == "import"
    assert tool_run.tool == "nessus"
    assert tool_run.status == "succeeded"
    assert len(obs) == 2  # 2 findings on 172.30.0.10
    assert skipped == ["192.168.1.50"]

    with sessions() as session:
        events = list_audit_events(session, assessment.id)
        skip_event = next(
            (e for e in events if e.event_type == "nessus.host_skipped_out_of_scope"), None
        )
        assert skip_event is not None
        assert skip_event.detail["host"] == "192.168.1.50"


def test_openvas_importer_with_scope_skipping(test_env):
    """OpenVAS importer extracts findings for in-scope hosts and skips out-of-scope hosts."""
    settings, engine, sessions = test_env
    importer = OpenVasImporter(settings=settings, data_dir=settings.data_dir)
    sample_file = SAMPLES_DIR / "sample_openvas.xml"
    content = sample_file.read_bytes()

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="OpenVAS Import Test", description="Testing OpenVAS")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],  # 10.99.99.99 is NOT in scope
                allowed_tools=["openvas"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

        tool_run, obs, skipped = importer.import_file(
            session, assessment.id, "sample_openvas.xml", content
        )

    assert tool_run.mode == "import"
    assert tool_run.tool == "openvas"
    assert len(obs) == 1
    assert "CVE-2021-41773" in obs[0].cve_ids
    assert skipped == ["10.99.99.99"]


def test_burp_importer_with_scope_skipping(test_env):
    """Burp Suite importer imports in-scope issues and skips excluded targets."""
    settings, engine, sessions = test_env
    importer = BurpImporter(settings=settings, data_dir=settings.data_dir)
    sample_file = SAMPLES_DIR / "sample_burp.xml"
    content = sample_file.read_bytes()

    with sessions.begin() as session:
        assessment = create_assessment(
            session, AssessmentCreate(name="Burp Import Test", description="Testing Burp")
        )
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],  # 192.168.99.100 is NOT in scope
                allowed_tools=["burp"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

        tool_run, obs, skipped = importer.import_file(
            session, assessment.id, "sample_burp.xml", content
        )

    assert tool_run.mode == "import"
    assert tool_run.tool == "burp"
    assert len(obs) == 1
    assert "Cross-site scripting" in obs[0].title
    assert obs[0].category == "owasp_top10"
    assert skipped == ["192.168.99.100"]


def test_xxe_payload_rejection():
    """Verify that defusedxml blocks external entity expansion (XXE)."""
    xxe_payload = b"""<?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <NessusClientData_v2>
      <Report name="XXE Attack">
        <ReportHost name="&xxe;">
        </ReportHost>
      </Report>
    </NessusClientData_v2>"""

    importer = NessusImporter()
    with pytest.raises(ValueError) as exc:
        importer.parse_content(xxe_payload)
    assert "Failed to parse Nessus XML" in str(exc.value) or "EntitiesForbidden" in str(exc.value)


def test_imports_api_multipart(test_env):
    """Test POST /assessments/{id}/imports multipart endpoint."""
    settings, engine, sessions = test_env
    app = create_app(settings=settings, engine=engine)
    sample_file = SAMPLES_DIR / "sample.nessus"

    with TestClient(app) as client:
        with sessions.begin() as session:
            assessment = create_assessment(
                session, AssessmentCreate(name="API Import", description="Testing API")
            )
            register_scope(
                session,
                assessment.id,
                ScopeRules(
                    allowed_targets=["172.30.0.10"],
                    allowed_tools=["nessus"],
                    allowed_action_classes=["discovery"],
                ),
                settings=settings,
            )

        with open(sample_file, "rb") as fh:
            resp = client.post(
                f"/assessments/{assessment.id}/imports",
                files={"file": ("sample.nessus", fh, "application/xml")},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["tool_run"]["mode"] == "import"
        assert data["tool_run"]["tool"] == "nessus"
        assert data["observations_count"] == 2
        assert "192.168.1.50" in data["skipped_hosts"]
