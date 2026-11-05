"""Deterministic scope-engine tests for Prompt 3."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import create_database_engine, create_session_factory, initialize_database
from app.main import create_app
from app.models.schemas import AssessmentCreate
from app.repo.assessments import create_assessment
from app.repo.audit import list_audit_events, verify_chain
from app.scope.enforcement import (
    ScopeGuardError,
    ScopeToken,
    require_scope,
    run_tool,
)
from app.scope.engine import (
    ScopeDenied,
    ScopeRegistrationError,
    check_action,
    register_scope,
    revalidate_at_execution,
)
from app.scope.models import Decision, ScopeRules
from app.settings import Settings


@pytest.fixture
def env(tmp_path: Path) -> Iterator[tuple[Settings, Engine, sessionmaker[Session]]]:
    """Provide isolated SQLite storage and default lab settings."""
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'scope.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="10.0.0.0/16",
        allow_public_targets=False,
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    yield settings, engine, sessions
    engine.dispose()


def make_assessment(session: Session, name: str = "Test Assessment") -> str:
    """Helper to create an assessment and return its ID."""
    created = create_assessment(session, AssessmentCreate(name=name))
    return created.id


def default_rules(
    *,
    allowed_targets: list[str] | None = None,
    exclusions: list[str] | None = None,
    allowed_tools: list[str] | None = None,
    allowed_action_classes: list[str] | None = None,
    **kwargs: Any,
) -> ScopeRules:
    """Build a default ScopeRules document."""
    return ScopeRules(
        allowed_targets=allowed_targets or ["10.0.1.0/24"],
        exclusions=exclusions or [],
        allowed_tools=allowed_tools or ["nmap"],
        allowed_action_classes=allowed_action_classes or ["discovery"],  # type: ignore[arg-type]
        **kwargs,
    )


def test_in_scope_ip_allowed_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """An IP inside the allowed CIDR is allowed and generates an audit event."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(session, asm_id, default_rules(), settings=settings)

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.50",
            action_class="discovery",
            args=["-sV", "-p", "80"],
            settings=settings,
        )

        assert decision.allowed is True
        assert decision.outcome == "allowed"

        events = list_audit_events(session, asm_id)
        check_events = [e for e in events if e.event_type == "scope.check_action"]
        assert len(check_events) == 1
        assert check_events[0].outcome == "allowed"
        assert check_events[0].detail["target"] == "10.0.1.50"
        assert verify_chain(session, asm_id) is True


def test_out_of_scope_ip_denied_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """An IP outside the allowed set is denied and generates an audit event."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(session, asm_id, default_rules(), settings=settings)

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.2.50",
            action_class="discovery",
            settings=settings,
        )

        assert decision.allowed is False
        assert decision.outcome == "denied"
        assert "not in the allowed set" in decision.reason

        events = list_audit_events(session, asm_id)
        check_events = [e for e in events if e.event_type == "scope.check_action"]
        assert len(check_events) == 1
        assert check_events[0].outcome == "denied"
        assert verify_chain(session, asm_id) is True


def test_excluded_host_inside_allowed_cidr_denied(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Exclusions always win over allows even when target is in an allowed CIDR."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)
        rules = default_rules(
            allowed_targets=["10.0.1.0/24"],
            exclusions=["10.0.1.99"],
        )
        register_scope(session, asm_id, rules, settings=settings)

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.99",
            action_class="discovery",
            settings=settings,
        )

        assert decision.allowed is False
        assert decision.outcome == "denied"
        assert "target is excluded" in decision.reason

        events = list_audit_events(session, asm_id)
        check_events = [e for e in events if e.event_type == "scope.check_action"]
        assert len(check_events) == 1
        assert check_events[0].outcome == "denied"
        assert verify_chain(session, asm_id) is True


def test_public_ip_rejected_at_registration(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Public IPs and CIDRs outside LAB_CIDR must be rejected during registration."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)

        # Public IP
        rules_ip = default_rules(allowed_targets=["8.8.8.8"])
        with pytest.raises(
            ScopeRegistrationError, match="public IPs/CIDRs are not inside LAB_CIDR"
        ):
            register_scope(session, asm_id, rules_ip, settings=settings)

        # Public CIDR
        rules_cidr = default_rules(allowed_targets=["93.184.216.0/24"])
        with pytest.raises(
            ScopeRegistrationError, match="public IPs/CIDRs are not inside LAB_CIDR"
        ):
            register_scope(session, asm_id, rules_cidr, settings=settings)


def test_overly_broad_ranges_rejected_at_registration(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """0.0.0.0/0 and ranges larger than /16 are rejected at registration."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)

        # 0.0.0.0/0
        with pytest.raises(ScopeRegistrationError, match="0.0.0.0/0 and equivalent ranges"):
            register_scope(
                session,
                asm_id,
                default_rules(allowed_targets=["0.0.0.0/0"]),
                settings=settings,
            )

        # IPv4 range larger than /16 (e.g. /8)
        with pytest.raises(ScopeRegistrationError, match="larger than /16 are not allowed"):
            register_scope(
                session,
                asm_id,
                default_rules(allowed_targets=["10.0.0.0/8"]),
                settings=settings,
            )


def test_hostname_resolving_outside_scope_denied_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """A registered hostname that resolves to a public or non-lab IP is blocked."""
    settings, _engine, sessions = env

    def mock_resolver(name: str) -> list[str]:
        if name == "lab-service.local":
            # Resolves to a public IP outside scope
            return ["93.184.216.34"]
        return ["10.0.1.20"]

    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(
            session,
            asm_id,
            default_rules(allowed_targets=["lab-service.local"]),
            settings=settings,
        )

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="lab-service.local",
            action_class="discovery",
            settings=settings,
            resolve=mock_resolver,
        )

        assert decision.allowed is False
        assert decision.outcome == "denied"
        assert "outside scope" in decision.reason or "public IP" in decision.reason

        events = list_audit_events(session, asm_id)
        check_events = [e for e in events if e.event_type == "scope.check_action"]
        assert len(check_events) == 1
        assert check_events[0].outcome == "denied"
        assert verify_chain(session, asm_id) is True


def test_cloud_metadata_ip_blocked(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Cloud metadata IP 169.254.169.254 is blocked by default."""
    settings, _engine, sessions = env

    with sessions.begin() as session:
        asm_id = make_assessment(session)

        # Direct registration is rejected
        with pytest.raises(ScopeRegistrationError, match="cloud-metadata"):
            register_scope(
                session,
                asm_id,
                default_rules(allowed_targets=["169.254.169.254"]),
                settings=settings,
            )

        # If a hostname dynamically resolves to 169.254.169.254 at execution
        register_scope(
            session,
            asm_id,
            default_rules(allowed_targets=["meta-spoof.lab"]),
            settings=settings,
        )

        def mock_meta_resolver(name: str) -> list[str]:
            return ["169.254.169.254"]

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="meta-spoof.lab",
            action_class="discovery",
            settings=settings,
            resolve=mock_meta_resolver,
        )

        assert decision.allowed is False
        assert "cloud-metadata" in decision.reason

        events = list_audit_events(session, asm_id)
        assert any(e.outcome == "denied" for e in events)
        assert verify_chain(session, asm_id) is True


def test_disallowed_action_class_denied_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Action classes not present in the scope's allowed list are denied."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)
        rules = default_rules(allowed_action_classes=["discovery"])
        register_scope(session, asm_id, rules, settings=settings)

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="active_validation",
            settings=settings,
        )

        assert decision.allowed is False
        assert "action class is not allowlisted" in decision.reason

        events = list_audit_events(session, asm_id)
        assert any(e.outcome == "denied" for e in events)
        assert verify_chain(session, asm_id) is True


def test_disallowed_tool_denied_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Tools not present in allowed_tools are denied."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)
        rules = default_rules(allowed_tools=["nmap"])
        register_scope(session, asm_id, rules, settings=settings)

        decision = check_action(
            session,
            asm_id,
            tool="sqlmap",
            target="10.0.1.10",
            action_class="discovery",
            settings=settings,
        )

        assert decision.allowed is False
        assert "tool is not allowlisted" in decision.reason

        events = list_audit_events(session, asm_id)
        assert any(e.outcome == "denied" for e in events)
        assert verify_chain(session, asm_id) is True


def test_unsafe_nmap_flags_rejected_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Unsafe or unallowlisted Nmap flags are rejected by the args sanitizer and audited."""
    settings, _engine, sessions = env
    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(session, asm_id, default_rules(), settings=settings)

        # Unallowlisted flag
        d1 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            args=["-sS"],
            settings=settings,
        )
        assert d1.allowed is False
        assert "flag -sS is not allowlisted" in d1.reason

        # Rejected NSE category: vuln
        d2 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            args=["--script", "vuln"],
            settings=settings,
        )
        assert d2.allowed is False
        assert "rejected by default" in d2.reason

        # Rejected NSE category: exploit
        d3 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            args=["--script", "exploit"],
            settings=settings,
        )
        assert d3.allowed is False
        assert "rejected by default" in d3.reason

        # Safe Nmap flags allowed
        d4 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            args=[
                "-sV",
                "-sT",
                "-Pn",
                "-p",
                "80,443",
                "--top-ports",
                "100",
                "-T3",
                "-oX",
                "scan.xml",
                "--script",
                "default,safe",
            ],
            settings=settings,
        )
        assert d4.allowed is True

        events = list_audit_events(session, asm_id)
        check_events = [e for e in events if e.event_type == "scope.check_action"]
        assert len(check_events) == 4
        assert [e.outcome for e in check_events] == ["denied", "denied", "denied", "allowed"]
        assert verify_chain(session, asm_id) is True


def test_url_redirect_leaving_scope_denied_and_audited(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Redirects leaving the registered scope are detected and denied."""
    settings, _engine, sessions = env

    def mock_redirect_resolver(name: str) -> list[str]:
        if name == "target.lab":
            return ["10.0.1.10"]
        if name == "external.com":
            return ["93.184.216.34"]
        return ["10.0.1.10"]

    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(
            session,
            asm_id,
            default_rules(allowed_targets=["http://target.lab/app"]),
            settings=settings,
        )

        decision = check_action(
            session,
            asm_id,
            tool="nmap",
            target="http://target.lab/app",
            action_class="discovery",
            redirects=["http://target.lab/login", "https://external.com/phish"],
            settings=settings,
            resolve=mock_redirect_resolver,
        )

        assert decision.allowed is False
        assert "redirect leaving scope" in decision.reason

        events = list_audit_events(session, asm_id)
        check_events = [e for e in events if e.event_type == "scope.check_action"]
        assert len(check_events) == 1
        assert check_events[0].outcome == "denied"
        assert verify_chain(session, asm_id) is True


def test_revalidate_at_execution_catches_rebinding(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """revalidate_at_execution re-resolves and rejects dynamic changes to unsafe addresses."""
    settings, _engine, sessions = env

    def initial_resolver(name: str) -> list[str]:
        return ["10.0.1.15"]

    def rebound_resolver(name: str) -> list[str]:
        return ["169.254.169.254"]

    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(
            session,
            asm_id,
            default_rules(allowed_targets=["rebind.lab"]),
            settings=settings,
        )

        d1 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="rebind.lab",
            action_class="discovery",
            settings=settings,
            resolve=initial_resolver,
        )
        assert d1.allowed is True

        d2 = revalidate_at_execution(
            session,
            asm_id,
            tool="nmap",
            target="rebind.lab",
            action_class="discovery",
            settings=settings,
            resolve=rebound_resolver,
        )
        assert d2.allowed is False
        assert "cloud-metadata" in d2.reason
        assert verify_chain(session, asm_id) is True


def test_time_window_and_rate_limit(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """Time window boundaries and rate limits are deterministically enforced."""
    settings, _engine, sessions = env
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)

    with sessions.begin() as session:
        asm_id = make_assessment(session)
        rules = default_rules(
            window_start=now - timedelta(hours=1),
            window_end=now + timedelta(hours=1),
            rate_limit_max=2,
            rate_limit_window_seconds=60,
        )
        register_scope(session, asm_id, rules, settings=settings)

        # Before window
        d_early = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            now=now - timedelta(hours=2),
            settings=settings,
        )
        assert d_early.allowed is False
        assert "time window" in d_early.reason

        # In window, call 1
        d_ok1 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            now=now,
            settings=settings,
        )
        assert d_ok1.allowed is True

        # In window, call 2
        d_ok2 = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            now=now + timedelta(seconds=10),
            settings=settings,
        )
        assert d_ok2.allowed is True

        # In window, call 3 (rate limit exceeded)
        d_rate = check_action(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.10",
            action_class="discovery",
            now=now + timedelta(seconds=20),
            settings=settings,
        )
        assert d_rate.allowed is False
        assert "rate limit exceeded" in d_rate.reason
        assert verify_chain(session, asm_id) is True


def test_require_scope_enforcement_guard(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """A tool runner cannot execute without a valid ScopeToken from require_scope."""
    settings, _engine, sessions = env

    executed = False

    def sample_tool() -> str:
        nonlocal executed
        executed = True
        return "tool output"

    # Attempting to run without a token raises ScopeGuardError
    with pytest.raises(ScopeGuardError, match="tool cannot run without require_scope"):
        run_tool(None, sample_tool)
    assert executed is False

    # Attempting to run with an invalid or spoofed token raises ScopeGuardError
    fake_token = ScopeToken(
        assessment_id="ASM-FAKE",
        tool="nmap",
        target="10.0.1.10",
        decision=Decision.allow("spoofed"),
        _marker="wrong_marker",
    )
    with pytest.raises(ScopeGuardError, match="tool cannot run without require_scope"):
        run_tool(fake_token, sample_tool)
    assert executed is False

    with sessions.begin() as session:
        asm_id = make_assessment(session)
        register_scope(session, asm_id, default_rules(), settings=settings)

        # Out-of-scope target raises ScopeDenied
        with pytest.raises(ScopeDenied):
            require_scope(
                session,
                asm_id,
                tool="nmap",
                target="10.0.99.99",
                action_class="discovery",
                settings=settings,
            )

        # In-scope target produces valid ScopeToken and tool executes
        token = require_scope(
            session,
            asm_id,
            tool="nmap",
            target="10.0.1.50",
            action_class="discovery",
            args=["-sV"],
            settings=settings,
        )
        assert isinstance(token, ScopeToken)
        result = run_tool(token, sample_tool)
        assert result == "tool output"
        assert executed is True
        assert verify_chain(session, asm_id) is True


def test_scope_api_endpoints_round_trip(
    env: tuple[Settings, Engine, sessionmaker[Session]],
) -> None:
    """FastAPI endpoints for assessment creation, scope registration, retrieval, and check."""
    settings, engine, _sessions = env
    app = create_app(settings=settings, engine=engine)

    with TestClient(app) as client:
        # 1. POST /assessments
        resp = client.post(
            "/assessments", json={"name": "API Assessment", "description": "Via API"}
        )
        assert resp.status_code == 200
        data = resp.json()
        asm_id = data["id"]
        assert data["name"] == "API Assessment"

        # 2. POST /assessments/{id}/scope
        scope_payload = {
            "allowed_targets": ["10.0.1.0/24"],
            "exclusions": ["10.0.1.100"],
            "allowed_tools": ["nmap"],
            "allowed_action_classes": ["discovery", "vuln_scan"],
            "notes": "Registered via HTTP endpoint",
        }
        resp = client.post(f"/assessments/{asm_id}/scope", json=scope_payload)
        assert resp.status_code == 200
        scope_data = resp.json()
        assert scope_data["assessment_id"] == asm_id
        assert scope_data["allowed_targets"] == ["10.0.1.0/24"]

        # 3. GET /assessments/{id}/scope
        resp = client.get(f"/assessments/{asm_id}/scope")
        assert resp.status_code == 200
        assert resp.json()["id"] == scope_data["id"]

        # 4. POST /assessments/{id}/scope/check (allowed)
        check_payload = {
            "tool": "nmap",
            "target": "10.0.1.25",
            "action_class": "discovery",
            "args": ["-sV", "-Pn"],
        }
        resp = client.post(f"/assessments/{asm_id}/scope/check", json=check_payload)
        assert resp.status_code == 200
        decision = resp.json()
        assert decision["allowed"] is True
        assert decision["outcome"] == "allowed"

        # 5. POST /assessments/{id}/scope/check (denied - excluded target)
        check_denied = {
            "tool": "nmap",
            "target": "10.0.1.100",
            "action_class": "discovery",
            "args": ["-sV"],
        }
        resp = client.post(f"/assessments/{asm_id}/scope/check", json=check_denied)
        assert resp.status_code == 200
        decision_denied = resp.json()
        assert decision_denied["allowed"] is False
        assert decision_denied["outcome"] == "denied"
        assert "target is excluded" in decision_denied["reason"]

    # Verify audit chain integrity
    factory = create_session_factory(engine)
    with factory() as session:
        assert verify_chain(session, asm_id) is True
