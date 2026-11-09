"""End-to-end test covering the full VAPT assessment lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.metasploit import MetasploitAdapter
from app.agent.client import AgentResponse, MockLLMClient, ToolCall
from app.agent.orchestrator import AgentOrchestrator
from app.approvals.service import create_approval_request
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
    ToolRunCreate,
)
from app.pipeline.risk import recalculate_assessment_risks
from app.raw_output import RawOutputStore
from app.repo import (
    append_audit_event,
    attach_tool_run_raw_output,
    create_assessment,
    create_asset,
    create_finding,
    create_tool_run,
)
from app.reports.generator import generate_report_pdf, render_report_html
from app.settings import Settings

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def e2e_env(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "test_e2e.db"
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{db_path}",
        data_dir=data_dir,
        lab_cidr="172.30.0.0/24",
        enable_active_validation=True,
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    configure_session_factory(engine)
    sessions = create_session_factory(engine)
    app = create_app(settings=settings, engine=engine)
    client = TestClient(app)
    store = RawOutputStore(data_dir)

    return settings, engine, sessions, client, store


def test_full_vapt_assessment_lifecycle(e2e_env):
    """Walk through the complete lifecycle from scoping to PDF report generation."""
    settings, _, sessions, client, store = e2e_env

    # 1. Create Assessment
    with sessions.begin() as session:
        asm = create_assessment(session, AssessmentCreate(name="E2E Security Audit"))
        asm_id = asm.id

    # 2. Register Scope Rules (CIDR 172.30.0.0/24)
    scope_payload = {
        "allowed_targets": ["172.30.0.0/24"],
        "exclusions": ["172.30.0.254"],
        "allowed_tools": ["nmap", "nikto", "zap", "metasploit"],
        "allowed_action_classes": ["discovery", "vuln_scan", "web_scan", "active_validation"],
        "notes": "E2E testing scope authorization",
    }
    resp_scope = client.post(f"/assessments/{asm_id}/scope", json=scope_payload)
    assert resp_scope.status_code == 200

    # 3. Verify Deterministic Scope Check Enforcement
    # Out of scope target
    resp_check_out = client.post(
        f"/assessments/{asm_id}/scope/check",
        json={"target": "8.8.8.8", "tool": "nmap", "action_class": "discovery"},
    )
    assert resp_check_out.status_code == 200
    assert resp_check_out.json()["allowed"] is False
    assert "outside LAB_CIDR" in resp_check_out.json()["reason"]

    # In scope target
    resp_check_in = client.post(
        f"/assessments/{asm_id}/scope/check",
        json={"target": "172.30.0.10", "tool": "nmap", "action_class": "discovery"},
    )
    assert resp_check_in.status_code == 200
    assert resp_check_in.json()["allowed"] is True

    # 4. Agent Reasoning: Propose Assessment Plan
    import asyncio

    mock_llm = MockLLMClient()
    mock_llm.queue_response(
        AgentResponse(
            content="[INFERENCE] I propose an initial discovery and service scan plan.",
            tool_calls=[
                ToolCall(
                    id="call_1",
                    name="propose_plan",
                    arguments={
                        "title": "Lab Assessment Plan",
                        "steps": [
                            {
                                "action": "nmap",
                                "target": "172.30.0.10",
                                "rationale": "Discover active hosts and open TCP ports.",
                                "arguments": {"top_ports": 100},
                            },
                            {
                                "action": "zap",
                                "target": "http://172.30.0.10",
                                "rationale": "Passive web vulnerability crawl on HTTP service.",
                                "arguments": {},
                            },
                        ],
                    },
                )
            ],
        )
    )
    orchestrator = AgentOrchestrator(client=mock_llm, settings=settings)
    with sessions.begin() as session:
        resp_turn, hallucinations = asyncio.run(
            orchestrator.run_turn(
                session=session,
                assessment_id=asm_id,
                user_message="Assess 172.30.0.10",
            )
        )
    assert len(resp_turn.tool_calls) == 1
    assert resp_turn.tool_calls[0].name == "propose_plan"
    assert hallucinations == []

    # 5. Execute Scan & Ingest Correlated Finding
    with sessions.begin() as session:
        ast = create_asset(
            session,
            AssetCreate(
                assessment_id=asm_id,
                identifier="172.30.0.10",
                asset_type="ip",
                attributes={"criticality": "high", "internet_facing": True},
                first_seen=NOW,
                last_seen=NOW,
            ),
        )
        tr = create_tool_run(
            session,
            ToolRunCreate(
                tool="nmap",
                assessment_id=asm_id,
                mode="live",
                status="succeeded",
                args=["-sV", "172.30.0.10"],
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        ev_bytes = (
            b"critical CVE-2021-41773 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H "
            b"Apache 2.4.49 path traversal RCE"
        )
        ev_file = store.store(assessment_id=asm_id, tool_run_id=tr.id, content=ev_bytes)
        attach_tool_run_raw_output(session, tr.id, ev_file)

        append_audit_event(
            session,
            assessment_id=asm_id,
            actor="agent",
            event_type="scan_completed",
            detail={"tool": "nmap", "target": "172.30.0.10"},
            outcome="success",
        )

        fc = FindingCreate(
            assessment_id=asm_id,
            title="Apache Path Traversal and RCE",
            description="Remote code execution in Apache HTTP Server 2.4.49.",
            category="outdated_software",
            asset_id=ast.id,
            port=80,
            protocol="tcp",
            source_tools=["nmap"],
            source_refs=[
                FindingSourceInput(
                    raw_ref=RawReference(
                        tool_run_id=tr.id,
                        locator="line 1",
                    )
                )
            ],
            raw_refs=[
                RawReference(
                    tool_run_id=tr.id,
                    locator="line 1",
                )
            ],
            cve_ids=["CVE-2021-41773"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            tool_severity="critical",
            confidence="high",
            confidence_score=0.95,
            confidence_reason="Direct scanner verification",
            status="confirmed",
            validation_status="not_validated",
            evidence=[
                EvidenceCreate(
                    type="observed",
                    content="Apache 2.4.49 detected on port 80",
                    timestamp=NOW,
                    raw_ref=RawReference(
                        tool_run_id=tr.id,
                        locator="line 1",
                    ),
                ),
                EvidenceCreate(
                    type="inference",
                    content="Known unauthenticated RCE exploit available",
                    timestamp=NOW,
                ),
            ],
            first_seen=NOW,
            last_seen=NOW,
        )
        finding = create_finding(session, fc, data_dir=store.data_dir)
        finding_id = finding.id

    # 6. Recalculate Risk Engine
    with sessions.begin() as session:
        recalculate_assessment_risks(session, asm_id)

    # Verify Findings API returns prioritized findings
    resp_fnd = client.get(f"/assessments/{asm_id}/findings?sort=risk")
    assert resp_fnd.status_code == 200
    findings_list = resp_fnd.json()
    assert len(findings_list) == 1
    assert findings_list[0]["risk_score"] > 80.0
    assert findings_list[0]["risk_band"] == "P1 Critical"

    # 7. Human-in-the-Loop Approval Gate for Active Validation
    msf_adapter = MetasploitAdapter(settings=settings)

    # Create approval request
    with sessions.begin() as session:
        req = create_approval_request(
            session=session,
            assessment_id=asm_id,
            finding_id=finding_id,
            tool="metasploit",
            target="172.30.0.10",
            params={"module": "exploit/multi/http/apache_normalize_path_rce"},
            justification="Verify remote code execution safely",
            risk="high",
        )
        appr_id = req.id

    # Attempting execution before approval must fail
    with pytest.raises(PermissionError):
        with sessions() as session:
            asyncio.run(
                msf_adapter.run_validation(
                    session=session,
                    assessment_id=asm_id,
                    finding_id=finding_id,
                    target="172.30.0.10",
                    approval_id=appr_id,
                    params={"module": "exploit/multi/http/apache_normalize_path_rce"},
                )
            )

    # Approve request via API
    resp_decide = client.post(
        f"/approvals/{appr_id}/decision",
        json={
            "decision": "approve",
            "reason": "Authorized lab validation",
            "approver": "sec_analyst",
        },
    )
    assert resp_decide.status_code == 200

    # Run check module with approved approval token -> succeeds safely
    with sessions.begin() as session:
        tool_run, confirmed = asyncio.run(
            msf_adapter.run_validation(
                session=session,
                assessment_id=asm_id,
                finding_id=finding_id,
                target="172.30.0.10",
                approval_id=appr_id,
                params={"module": "exploit/multi/http/apache_normalize_path_rce"},
            )
        )
    assert confirmed is True
    assert tool_run.status == "succeeded"

    # 8. Generate Report (Preview and Downloadable PDF)
    with sessions() as session:
        html = render_report_html(session, asm_id)
        assert "OBSERVED EVIDENCE" in html
        assert "AI INFERENCE" in html
        assert "CVE-2021-41773" in html

        pdf_bytes = generate_report_pdf(session, asm_id)
        assert len(pdf_bytes) > 500
        assert pdf_bytes.startswith(b"%PDF-")

    # 9. Verify Cryptographic SHA-256 Audit Chain
    resp_ver = client.get(f"/assessments/{asm_id}/audit/verify")
    assert resp_ver.status_code == 200
    assert resp_ver.json()["verified"] is True
    assert resp_ver.json()["event_count"] >= 3

    # 10. Check Integration Matrix API
    resp_matrix = client.get("/integrations")
    assert resp_matrix.status_code == 200
    matrix = resp_matrix.json()
    assert len(matrix) == 7
