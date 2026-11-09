"""Unit tests for the VAPT Report Generator."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import (
    configure_session_factory,
    create_database_engine,
    create_session_factory,
    initialize_database,
)
from app.main import create_app
from app.models.schemas import (
    AssessmentCreate,
    AssetCreate,
    EvidenceCreate,
    FindingCreate,
    FindingSourceInput,
    RawReference,
    ScopeRuleCreate,
    ToolRunCreate,
)
from app.raw_output import RawOutputStore
from app.repo import (
    append_audit_event,
    attach_tool_run_raw_output,
    create_assessment,
    create_asset,
    create_finding,
    create_tool_run,
    upsert_scope_rules,
)
from app.reports.generator import (
    UngroundedReportError,
    generate_report_pdf,
    render_report_html,
)
from app.settings import Settings

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def test_env(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "test_reports.db"
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{db_path}",
        data_dir=data_dir,
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    configure_session_factory(engine)
    sessions = create_session_factory(engine)
    app = create_app(settings=settings, engine=engine)
    client = TestClient(app)
    store = RawOutputStore(data_dir)

    return settings, engine, sessions, client, store


def _setup_assessment_with_finding(sessions, store: RawOutputStore):
    with sessions.begin() as session:
        asm = create_assessment(session, AssessmentCreate(name="Acme Corp Pentest"))
        upsert_scope_rules(
            session,
            asm.id,
            ScopeRuleCreate(
                allowed_targets=["192.168.1.0/24"],
                exclusions=[],
                allowed_tools=["nmap", "zap"],
                allowed_action_classes=["discovery", "vuln_scan"],
            ),
        )
        ast = create_asset(
            session,
            AssetCreate(
                assessment_id=asm.id,
                identifier="192.168.1.50",
                asset_type="ip",
                attributes={"criticality": "high"},
                first_seen=NOW,
                last_seen=NOW,
            ),
        )
        tr = create_tool_run(
            session,
            ToolRunCreate(
                tool="nmap",
                assessment_id=asm.id,
                mode="live",
                status="succeeded",
                args=["-sV", "192.168.1.50"],
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        ev_file = store.store(
            assessment_id=asm.id,
            tool_run_id=tr.id,
            content=(
                b"high CVE-2021-41773 7.5 "
                b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N Apache 2.4.49"
            ),
        )
        attach_tool_run_raw_output(session, tr.id, ev_file)

        append_audit_event(
            session,
            assessment_id=asm.id,
            actor="system",
            event_type="assessment_created",
            detail={"name": asm.name},
            outcome="success",
        )

        fc = FindingCreate(
            assessment_id=asm.id,
            title="Apache Path Traversal",
            description="Path traversal and file disclosure vulnerability.",
            category="outdated_software",
            asset_id=ast.id,
            port=80,
            protocol="tcp",
            source_tools=["nmap"],
            source_refs=[
                FindingSourceInput(
                    raw_ref=RawReference(
                        tool_run_id=tr.id,
                        locator="line 42",
                    )
                )
            ],
            raw_refs=[
                RawReference(
                    tool_run_id=tr.id,
                    locator="line 42",
                )
            ],
            cve_ids=["CVE-2021-41773"],
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            tool_severity="high",
            confidence="high",
            confidence_score=0.95,
            confidence_reason="Direct scanner verification",
            status="confirmed",
            validation_status="not_validated",
            evidence=[
                EvidenceCreate(
                    type="observed",
                    content="Apache 2.4.49 path traversal detected on port 80",
                    timestamp=NOW,
                    raw_ref=RawReference(
                        tool_run_id=tr.id,
                        locator="line 42",
                    ),
                ),
                EvidenceCreate(
                    type="inference",
                    content="High exploitability due to public POCs for CVE-2021-41773",
                    timestamp=NOW,
                ),
            ],
            first_seen=NOW,
            last_seen=NOW,
        )
        finding = create_finding(session, fc, data_dir=store.data_dir)
        return asm.id, ast.id, tr.id, finding.id


def test_pdf_compiles_without_errors(test_env):
    """Prove that PDF compiles without errors and produces valid PDF bytes."""
    _, _, sessions, _, store = test_env
    asm_id, _, _, _ = _setup_assessment_with_finding(sessions, store)

    with sessions() as session:
        pdf_bytes = generate_report_pdf(session, asm_id)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 500
        # PDF magic byte signature %PDF-
        assert pdf_bytes.startswith(b"%PDF-")


def test_distinct_observed_and_inference_evidence_rendered(test_env):
    """Prove that observed evidence and AI inference sections are distinctly rendered."""
    _, _, sessions, _, store = test_env
    asm_id, _, _, finding_id = _setup_assessment_with_finding(sessions, store)

    with sessions() as session:
        html = render_report_html(session, asm_id)
        # HTML must contain distinct observed evidence tag and inference tag
        assert "OBSERVED EVIDENCE" in html
        assert "AI INFERENCE" in html
        assert "evidence-observed" in html
        assert "evidence-inference" in html
        assert "CVE-2021-41773" in html


def test_ungrounded_cve_fails_report_validation(test_env):
    """Prove that an ungrounded CVE in report narrative causes validation to fail."""
    _, _, sessions, _, store = test_env
    asm_id, _, _, _ = _setup_assessment_with_finding(sessions, store)

    # Narrative citing a fabricated/ungrounded CVE (not in DB findings)
    fabricated_narrative = (
        "During this scan we also identified critical vulnerability CVE-2099-99999 "
        "which allows unauthenticated remote root exploit."
    )

    with sessions() as session:
        with pytest.raises(UngroundedReportError) as exc_info:
            render_report_html(session, asm_id, executive_narrative=fabricated_narrative)

        assert "Ungrounded CVE" in str(exc_info.value)
        assert "CVE-2099-99999" in str(exc_info.value)


def test_report_api_endpoints(test_env):
    """Prove that report API endpoints return 200, valid JSON, HTML and PDF bytes."""
    _, _, sessions, client, store = test_env
    asm_id, _, _, _ = _setup_assessment_with_finding(sessions, store)

    # 1. POST /assessments/{id}/report
    resp_post = client.post(f"/assessments/{asm_id}/report")
    assert resp_post.status_code == 200
    post_data = resp_post.json()
    assert post_data["status"] == "generated"
    assert post_data["audit_chain_verified"] is True
    assert post_data["total_findings"] >= 1

    # 2. GET /assessments/{id}/report/preview
    resp_prev = client.get(f"/assessments/{asm_id}/report/preview")
    assert resp_prev.status_code == 200
    assert "text/html" in resp_prev.headers["content-type"]
    assert "OBSERVED EVIDENCE" in resp_prev.text
    assert "AI INFERENCE" in resp_prev.text

    # 3. GET /assessments/{id}/report.pdf
    resp_pdf = client.get(f"/assessments/{asm_id}/report.pdf")
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")
