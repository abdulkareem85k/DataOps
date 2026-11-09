"""Seed script to pre-populate realistic VAPT assessment demo data for hackathon judges."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.db import (
    configure_session_factory,
    create_database_engine,
    create_session_factory,
    initialize_database,
)
from app.models.schemas import (
    AssessmentCreate,
    AssetCreate,
    EvidenceCreate,
    FindingCreate,
    FindingSourceInput,
    RawReference,
    ScopeRuleCreate,
    ServiceCreate,
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
    create_service,
    create_tool_run,
    upsert_scope_rules,
    verify_chain,
)
from app.settings import get_settings

logger = logging.getLogger("vapt_agent.seed")
NOW = datetime.now(UTC)


def seed_demo_data() -> str:
    """Populate database with sample lab targets, scans, findings, and verified audit events."""
    settings = get_settings()
    engine = create_database_engine(settings)
    initialize_database(engine)
    configure_session_factory(engine)
    sessions = create_session_factory(engine)
    store = RawOutputStore(settings.data_dir)

    with sessions.begin() as session:
        # 1. Assessment
        asm = create_assessment(
            session,
            AssessmentCreate(
                name="OWASP Lab & Enterprise Infrastructure Assessment",
                description="Comprehensive multi-tool security evaluation of isolated lab targets.",
            ),
        )
        asm_id = asm.id

        # 2. Scope Rules
        upsert_scope_rules(
            session,
            asm_id,
            ScopeRuleCreate(
                allowed_targets=["172.30.0.0/24"],
                exclusions=["172.30.0.254"],
                allowed_tools=["nmap", "nikto", "zap", "nessus", "metasploit"],
                allowed_action_classes=["discovery", "vuln_scan", "web_scan", "active_validation"],
                notes="Authorized testing on internal security lab subnet",
            ),
        )

        append_audit_event(
            session,
            assessment_id=asm_id,
            actor="user",
            event_type="assessment_created",
            detail={"name": asm.name, "scope": "172.30.0.0/24"},
            outcome="success",
        )

        # 3. Discovered Assets & Services
        ast1 = create_asset(
            session,
            AssetCreate(
                assessment_id=asm_id,
                identifier="172.30.0.10",
                asset_type="ip",
                attributes={
                    "criticality": "critical",
                    "hostname": "juiceshop.lab",
                    "os": "Linux 5.15",
                },
                first_seen=NOW,
                last_seen=NOW,
            ),
        )
        svc1 = create_service(
            session,
            ServiceCreate(
                asset_id=ast1.id,
                port=3000,
                protocol="tcp",
                name="http",
                version="Node.js Express / OWASP Juice Shop",
            ),
        )

        ast2 = create_asset(
            session,
            AssetCreate(
                assessment_id=asm_id,
                identifier="172.30.0.20",
                asset_type="ip",
                attributes={"criticality": "high", "hostname": "dvwa.lab", "os": "Ubuntu 22.04"},
                first_seen=NOW,
                last_seen=NOW,
            ),
        )
        svc2 = create_service(
            session,
            ServiceCreate(
                asset_id=ast2.id,
                port=80,
                protocol="tcp",
                name="http",
                version="Apache/2.4.49 (Unix) PHP/8.1",
            ),
        )

        # 4. Tool Runs & Raw Artifacts
        tr_nmap = create_tool_run(
            session,
            ToolRunCreate(
                tool="nmap",
                assessment_id=asm_id,
                mode="live",
                status="succeeded",
                args=["-sV", "-T4", "172.30.0.0/24"],
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        nmap_raw = (
            b"Nmap scan report for juiceshop.lab (172.30.0.10)\n"
            b"PORT 3000/tcp open http Node.js Express\n"
            b"Nmap scan report for dvwa.lab (172.30.0.20)\n"
            b"PORT 80/tcp open http Apache 2.4.49 (Unix) CVE-2021-41773 9.8 "
            b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H critical\n"
        )
        nmap_ev = store.store(asm_id, tr_nmap.id, nmap_raw)
        attach_tool_run_raw_output(session, tr_nmap.id, nmap_ev)

        append_audit_event(
            session,
            assessment_id=asm_id,
            actor="agent",
            event_type="scan_completed",
            detail={"tool": "nmap", "target": "172.30.0.0/24"},
            outcome="success",
        )

        tr_zap = create_tool_run(
            session,
            ToolRunCreate(
                tool="zap",
                assessment_id=asm_id,
                mode="live",
                status="succeeded",
                args=["-cmd", "-quickurl", "http://172.30.0.10:3000"],
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        zap_raw = (
            b"ZAP 2.14.0 Report\n"
            b"URL: http://172.30.0.10:3000/rest/user/login\n"
            b"SQL Injection in 'email' parameter. CWE-89 high 8.5 "
            b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\n"
        )
        zap_ev = store.store(asm_id, tr_zap.id, zap_raw)
        attach_tool_run_raw_output(session, tr_zap.id, zap_ev)

        append_audit_event(
            session,
            assessment_id=asm_id,
            actor="agent",
            event_type="scan_completed",
            detail={"tool": "zap", "target": "http://172.30.0.10:3000"},
            outcome="success",
        )

        # 5. Correlated Findings
        # Finding 1: Apache Path Traversal & RCE
        fc1 = FindingCreate(
            assessment_id=asm_id,
            title="Apache HTTP Server Path Traversal and RCE",
            description=(
                "A path traversal and remote code execution flaw in Apache HTTP Server 2.4.49 "
                "allows an unauthenticated attacker to map URLs to files outside the document root."
            ),
            category="outdated_software",
            asset_id=ast2.id,
            service_id=svc2.id,
            port=80,
            protocol="tcp",
            source_tools=["nmap"],
            source_refs=[
                FindingSourceInput(
                    raw_ref=RawReference(
                        tool_run_id=tr_nmap.id,
                        locator="line 4",
                    )
                )
            ],
            raw_refs=[
                RawReference(
                    tool_run_id=tr_nmap.id,
                    locator="line 4",
                )
            ],
            cve_ids=["CVE-2021-41773"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            tool_severity="critical",
            confidence="high",
            confidence_score=0.95,
            confidence_reason="Corroborated by banner version check and exploit signatures",
            status="confirmed",
            validation_status="not_validated",
            evidence=[
                EvidenceCreate(
                    type="observed",
                    content=(
                        "PORT 80/tcp open http Apache 2.4.49 (Unix) CVE-2021-41773 9.8 critical"
                    ),
                    timestamp=NOW,
                    raw_ref=RawReference(
                        tool_run_id=tr_nmap.id,
                        locator="line 4",
                    ),
                ),
                EvidenceCreate(
                    type="inference",
                    content=(
                        "High probability of exploitation. Upgrade to Apache 2.4.51 "
                        "or disable path normalization immediately."
                    ),
                    timestamp=NOW,
                ),
            ],
            first_seen=NOW,
            last_seen=NOW,
        )
        finding_apache = create_finding(session, fc1, data_dir=store.data_dir)

        # Finding 2: SQL Injection
        fc2 = FindingCreate(
            assessment_id=asm_id,
            title="SQL Injection in User Authentication Endpoint",
            description=(
                "The email login parameter is improperly sanitized prior to SQL query execution, "
                "allowing authentication bypass and arbitrary database extraction."
            ),
            category="owasp_top10",
            asset_id=ast1.id,
            service_id=svc1.id,
            port=3000,
            protocol="tcp",
            url="http://172.30.0.10:3000/rest/user/login",
            parameter="email",
            source_tools=["zap"],
            source_refs=[
                FindingSourceInput(
                    raw_ref=RawReference(
                        tool_run_id=tr_zap.id,
                        locator="line 3",
                    )
                )
            ],
            raw_refs=[
                RawReference(
                    tool_run_id=tr_zap.id,
                    locator="line 3",
                )
            ],
            cwe_ids=["CWE-89"],
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            tool_severity="high",
            confidence="high",
            confidence_score=0.92,
            confidence_reason="DAST boolean-based error reflection observed",
            status="confirmed",
            validation_status="not_validated",
            evidence=[
                EvidenceCreate(
                    type="observed",
                    content="SQL Injection in 'email' parameter. CWE-89 high 8.5",
                    timestamp=NOW,
                    raw_ref=RawReference(
                        tool_run_id=tr_zap.id,
                        locator="line 3",
                    ),
                ),
                EvidenceCreate(
                    type="inference",
                    content="Enables complete compromise of customer credentials and PII data.",
                    timestamp=NOW,
                ),
            ],
            first_seen=NOW,
            last_seen=NOW,
        )
        create_finding(session, fc2, data_dir=store.data_dir)

        # 5b. Human Approval Request for Active Validation
        from app.approvals.service import create_approval_request
        create_approval_request(
            session=session,
            assessment_id=asm_id,
            finding_id=finding_apache.id,
            tool="metasploit",
            target="172.30.0.20:80",
            params={"RHOSTS": "172.30.0.20", "RPORT": 80, "TARGETURI": "/cgi-bin/.%2e/%2e%2e/etc/passwd"},
            justification="Confirm unauthenticated file read capability via harmless read-only proof on test lab.",
            risk="Active exploit execution against lab host. Requires human authorization.",
        )

    # 6. Recalculate Risk Engine
    with sessions.begin() as session:
        recalculate_assessment_risks(session, asm_id)

    # 7. Verify Integrity
    with sessions() as session:
        is_intact = verify_chain(session, asm_id)

    print("\n==================================================")
    print(" DEMO SEED COMPLETED SUCCESSFULLY")
    print(f" Assessment ID: {asm_id}")
    print(" Targets: 172.30.0.10 (Juice Shop), 172.30.0.20 (DVWA)")
    print(" Findings: 2 Critical/High findings seeded")
    print(f" Cryptographic Audit Chain: {'VERIFIED INTACT' if is_intact else 'BROKEN'}")
    print(" Web UI: http://localhost:5173")
    print("==================================================\n")
    return asm_id


if __name__ == "__main__":
    seed_demo_data()
