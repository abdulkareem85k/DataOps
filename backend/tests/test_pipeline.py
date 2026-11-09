"""Tests for normalization, multi-tool de-duplication, cross-host separation, and FP heuristics."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.db import create_database_engine, create_session_factory, initialize_database
from app.models.schemas import AssessmentCreate, RawObservation
from app.pipeline.correlate import correlate_findings
from app.pipeline.normalize import normalize_observation
from app.repo.assessments import create_assessment
from app.settings import Settings

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'pipeline.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_normalize_observation(test_env):
    """Normalize a RawObservation into a validated FindingCreate model."""
    settings, engine, sessions = test_env
    obs = RawObservation(
        tool="nmap",
        asset_identifier="172.30.0.10",
        asset_type="host",
        port=80,
        protocol="tcp",
        service_name="http",
        service_version="Apache/2.4.41",
        title="Apache Path Traversal",
        description="Path traversal vulnerability in Apache HTTP Server",
        severity="high",
        confidence="high",
        confidence_score=0.85,
        category="outdated_software",
        cve_ids=["CVE-2021-41773"],
        raw_ref={"tool_run_id": "TRN-nmap-1", "xpath": "//host/ports/port[@portid='80']"},
        evidence="Observed path traversal payload execution",
        timestamp=NOW,
    )

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Pipe Test"))
        finding = normalize_observation(session, assessment.id, obs)

    assert finding.title == "Apache Path Traversal"
    assert finding.category == "outdated_software"
    assert finding.cve_ids == ["CVE-2021-41773"]
    assert finding.source_tools == ["nmap"]
    assert len(finding.evidence) == 1
    assert finding.evidence[0].content == "Observed path traversal payload execution"
    assert finding.evidence[0].type == "observed"


def test_correlate_three_tools_merging_and_boost(test_env):
    """Findings from Nmap + Nessus + OpenVAS for the same issue on same host
    merge into 1 finding with 3 sources.
    """
    settings, engine, sessions = test_env

    # 1. Nmap observation
    obs_nmap = RawObservation(
        tool="nmap",
        asset_identifier="172.30.0.10",
        port=80,
        protocol="tcp",
        service_name="http",
        title="Nmap: Apache Path Traversal (CVE-2021-41773)",
        description="Nmap NSE detected path traversal vulnerability CVE-2021-41773",
        severity="medium",
        confidence="high",
        confidence_score=0.8,
        category="outdated_software",
        cve_ids=["CVE-2021-41773"],
        raw_ref={"tool_run_id": "TRN-nmap", "xpath": "//ports/port[@portid='80']"},
        evidence="Nmap script output: vulnerable to CVE-2021-41773",
        timestamp=NOW,
    )

    # 2. Nessus observation
    obs_nessus = RawObservation(
        tool="nessus",
        asset_identifier="172.30.0.10",
        port=80,
        protocol="tcp",
        service_name="http",
        title="Nessus: Apache HTTP Server Path Traversal",
        description="Nessus plugin 10001 confirmed CVE-2021-41773 with CVSS 7.5",
        severity="high",
        confidence="high",
        confidence_score=0.85,
        cvss_score=7.5,
        category="outdated_software",
        cve_ids=["CVE-2021-41773"],
        raw_ref={"tool_run_id": "TRN-nessus", "xpath": "//ReportItem[@pluginID='10001']"},
        evidence="Nessus plugin output: /icons/.%%32%65/etc/passwd returned 200",
        timestamp=NOW,
    )

    # 3. OpenVAS observation
    obs_openvas = RawObservation(
        tool="openvas",
        asset_identifier="172.30.0.10",
        port=80,
        protocol="tcp",
        service_name="http",
        title="OpenVAS: Apache Path Traversal Vulnerability",
        description="OpenVAS NVT detected CVE-2021-41773",
        severity="high",
        confidence="high",
        confidence_score=0.8,
        cvss_score=7.5,
        category="outdated_software",
        cve_ids=["CVE-2021-41773"],
        raw_ref={"tool_run_id": "TRN-openvas", "xpath": "//results/result[@id='res-1']"},
        evidence="OpenVAS report: vulnerable Apache HTTP Server 2.4.49",
        timestamp=NOW,
    )

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Correlation Test"))
        f_nmap = normalize_observation(session, assessment.id, obs_nmap)
        f_nessus = normalize_observation(session, assessment.id, obs_nessus)
        f_openvas = normalize_observation(session, assessment.id, obs_openvas)

    # Merge via correlate_findings
    merged = correlate_findings([f_nmap, f_nessus, f_openvas])

    # Must produce exactly 1 finding
    assert len(merged) == 1
    result = merged[0]

    # Check provenance
    assert sorted(result.source_tools) == ["nessus", "nmap", "openvas"]
    assert len(result.evidence) == 3
    assert len(result.raw_refs) == 3
    assert "CVE-2021-41773" in result.cve_ids
    assert result.cvss_score == 7.5

    # Multi-tool corroboration boost
    assert result.confidence == "high"
    assert result.confidence_score >= 0.95
    assert "Corroborated by 3 independent tools (nessus, nmap, openvas)" in result.confidence_reason


def test_cross_host_separation_and_linking(test_env):
    """The same vulnerability on 2 different hosts must NOT be merged;
    must remain 2 separate findings with related_to link.
    """
    settings, engine, sessions = test_env

    obs_host_a = RawObservation(
        tool="nmap",
        asset_identifier="172.30.0.10",
        port=80,
        protocol="tcp",
        title="Apache Path Traversal Host A",
        description="Vulnerability on Host A",
        severity="high",
        category="outdated_software",
        cve_ids=["CVE-2021-41773"],
        raw_ref={"tool_run_id": "TRN-1", "locator": "nmap:172.30.0.10:80"},
        evidence="Evidence on Host A",
        timestamp=NOW,
    )

    obs_host_b = RawObservation(
        tool="nmap",
        asset_identifier="172.30.0.20",  # Different host!
        port=80,
        protocol="tcp",
        title="Apache Path Traversal Host B",
        description="Vulnerability on Host B",
        severity="high",
        category="outdated_software",
        cve_ids=["CVE-2021-41773"],
        raw_ref={"tool_run_id": "TRN-1", "locator": "nmap:172.30.0.20:80"},
        evidence="Evidence on Host B",
        timestamp=NOW,
    )

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Cross-Host Test"))
        f_a = normalize_observation(session, assessment.id, obs_host_a)
        f_b = normalize_observation(session, assessment.id, obs_host_b)

    correlated = correlate_findings([f_a, f_b])

    # MUST remain 2 separate findings!
    assert len(correlated) == 2
    assert correlated[0].asset_id != correlated[1].asset_id

    # Must link them via related_to
    assert any("CVE-2021-41773" in rel for rel in correlated[0].related_to)
    assert any("CVE-2021-41773" in rel for rel in correlated[1].related_to)


def test_false_positive_heuristic_static_asset(test_env):
    """Missing security header on a purely static asset is flagged as likely_false_positive."""
    settings, engine, sessions = test_env
    obs = RawObservation(
        tool="nikto",
        asset_identifier="172.30.0.10",
        port=80,
        protocol="tcp",
        url="/icons/README",
        title="Nikto: The anti-clickjacking X-Frame-Options header is not present.",
        description="The anti-clickjacking X-Frame-Options header is not present.",
        severity="low",
        category="misconfig",
        raw_ref={"tool_run_id": "TRN-nikto", "locator": "nikto:172.30.0.10:80"},
        evidence="Header missing on /icons/README",
        timestamp=NOW,
    )

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="FP Test"))
        f = normalize_observation(session, assessment.id, obs)

    correlated = correlate_findings([f])
    assert len(correlated) == 1
    result = correlated[0]
    assert result.status == "likely_false_positive"
    assert "static asset" in result.confidence_reason
