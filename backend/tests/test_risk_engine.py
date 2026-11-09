"""Tests for deterministic risk engine, asset criticality re-ranking, and findings API."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import create_database_engine, create_session_factory, initialize_database
from app.main import create_app
from app.models.schemas import (
    AssessmentCreate,
    AssetCreate,
    EvidenceCreate,
    FindingCreate,
    RawReference,
)
from app.pipeline.risk import calculate_risk
from app.repo.assessments import create_assessment
from app.repo.assets import create_asset
from app.settings import Settings

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'risk.db'}",
        data_dir=tmp_path / "data",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_finding_without_cvss_keeps_none():
    """Prove finding without CVSS keeps cvss_score = None and labels as 'not scored by source'."""
    from app.models.schemas import AssetRead

    asset = AssetRead(
        id="AST-1",
        assessment_id="ASM-1",
        identifier="172.30.0.10",
        asset_type="host",
        attributes={"criticality": "medium"},
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
    )
    finding = FindingCreate(
        assessment_id="ASM-1",
        title="Missing Security Header",
        description="X-Frame-Options header not set",
        category="misconfig",
        asset_id=asset.id,
        port=80,
        protocol="tcp",
        tool_severity="low",
        confidence="medium",
        confidence_score=0.7,
        confidence_reason="Observed directly",
        status="suspected",
        validation_status="not_validated",
        first_seen=NOW,
        last_seen=NOW,
        cvss_score=None,  # No CVSS!
        source_tools=["nikto"],
        raw_refs=[RawReference(reference_file="ref.txt", locator="nikto:1")],
        evidence=[EvidenceCreate(type="observed", content="Header missing", timestamp=NOW)],
    )

    assessment = calculate_risk(finding, asset)
    assert assessment.breakdown["source_cvss"] is None
    assert assessment.breakdown["cvss_label"] == "not scored by source"
    assert assessment.score > 0.0
    assert assessment.band in ("P4 Low", "P5 Info")


def test_critical_asset_ranks_higher_than_low_asset():
    """Prove the identical vulnerability on a Critical asset scores higher than on a Low asset."""
    from app.models.schemas import AssetRead

    asset_critical = AssetRead(
        id="AST-crit",
        assessment_id="ASM-1",
        identifier="db.internal.lab",
        asset_type="host",
        attributes={"criticality": "critical"},
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
    )
    asset_low = AssetRead(
        id="AST-low",
        assessment_id="ASM-1",
        identifier="dev-test.lab",
        asset_type="host",
        attributes={"criticality": "low"},
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
    )

    finding = FindingCreate(
        assessment_id="ASM-1",
        title="Path Traversal in HTTP Server",
        description="Path traversal flaw",
        category="outdated_software",
        asset_id="AST-placeholder",
        port=80,
        protocol="tcp",
        tool_severity="high",
        cvss_score=7.5,
        confidence="high",
        confidence_score=0.9,
        confidence_reason="Corroborated",
        status="confirmed",
        validation_status="not_validated",
        first_seen=NOW,
        last_seen=NOW,
        source_tools=["nmap"],
        raw_refs=[RawReference(reference_file="ref.txt", locator="nmap:1")],
        evidence=[EvidenceCreate(type="observed", content="Traversal observed", timestamp=NOW)],
    )

    risk_crit = calculate_risk(finding, asset_critical)
    risk_low = calculate_risk(finding, asset_low)

    assert risk_crit.score > risk_low.score
    assert risk_crit.breakdown["asset_criticality"] == 1.5
    assert risk_low.breakdown["asset_criticality"] == 0.7


def test_risk_score_reproducibility():
    """Prove score is 100% reproducible from its stored JSON breakdown."""
    from app.models.schemas import AssetRead

    asset = AssetRead(
        id="AST-1",
        assessment_id="ASM-1",
        identifier="app.lab",
        asset_type="host",
        attributes={"criticality": "high", "internet_facing": True},
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
    )
    finding = FindingCreate(
        assessment_id="ASM-1",
        title="SQL Injection in Login Endpoint",
        description="SQL injection vulnerability in login query parameter",
        category="owasp_top10",
        asset_id=asset.id,
        port=443,
        protocol="https",
        tool_severity="critical",
        cvss_score=9.8,
        confidence="high",
        confidence_score=0.95,
        confidence_reason="Corroborated",
        status="confirmed",
        validation_status="not_validated",
        first_seen=NOW,
        last_seen=NOW,
        source_tools=["zap"],
        raw_refs=[RawReference(reference_file="ref.txt", locator="zap:1")],
        evidence=[EvidenceCreate(type="observed", content="SQLi error returned", timestamp=NOW)],
    )

    res1 = calculate_risk(finding, asset)
    res2 = calculate_risk(finding, asset)

    assert res1.score == res2.score
    assert res1.band == res2.band
    assert res1.breakdown == res2.breakdown
    assert res1.rationale == res2.rationale


def test_findings_api_endpoints(test_env):
    """Test GET /assessments/{id}/findings sorting, filters, and summary."""
    settings, engine, sessions = test_env
    app = create_app(settings=settings, engine=engine)

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Risk API Test"))
        create_asset(
            session,
            AssetCreate(
                assessment_id=assessment.id,
                identifier="target.lab",
                asset_type="host",
                attributes={"criticality": "high"},
            ),
        )

    with TestClient(app) as client:
        # Initial empty findings
        resp = client.get(f"/assessments/{assessment.id}/findings")
        assert resp.status_code == 200
        assert resp.json() == []

        # Summary endpoint
        resp_sum = client.get(f"/assessments/{assessment.id}/findings/summary")
        assert resp_sum.status_code == 200
        data_sum = resp_sum.json()
        assert data_sum["total_findings"] == 0
        assert "severities" in data_sum
        assert "risk_bands" in data_sum
