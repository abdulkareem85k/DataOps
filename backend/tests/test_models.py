"""Model and repository tests for Prompt 2 data contracts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, inspect, update
from sqlalchemy.orm import Session, sessionmaker

from app.db import create_database_engine, create_session_factory, initialize_database
from app.main import create_app
from app.models.orm import AuditEvent, Base
from app.models.schemas import AssessmentCreate, AssetCreate, FindingCreate, ToolRunCreate
from app.repo.audit import AuditRepository
from app.repo.common import InvalidRecordReference
from app.repo.findings import FindingRepository
from app.services import AssessmentService, AssetService, FindingService, ToolRunService
from app.settings import Settings
from tests.fixtures import make_finding_payload, seed_assessment_finding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "finding_roundtrip.json"
REQUIRED_TABLES = {
    "assessments",
    "scope_rules",
    "plans",
    "plan_steps",
    "tool_runs",
    "assets",
    "services",
    "findings",
    "evidence",
    "approvals",
    "audit_events",
    "decisions",
    "reports",
    "chat_messages",
}


@pytest.fixture
def store(tmp_path: Path) -> Iterator[tuple[Engine, sessionmaker[Session]]]:
    """Create an isolated SQLite/WAL database for one test."""
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'prompt2.db'}",
        data_dir=tmp_path / "data",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def read_fixture() -> dict[str, Any]:
    """Load the explicitly synthetic test-only assessment/finding fixture."""
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_declares_all_prompt2_tables() -> None:
    """All fourteen requested tables are part of SQLAlchemy metadata."""
    assert REQUIRED_TABLES <= set(Base.metadata.tables)


def test_backend_startup_creates_schema_before_health(tmp_path: Path) -> None:
    """The normal FastAPI lifespan initializes ORM tables before returning OK."""
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'startup.db'}",
        data_dir=tmp_path / "data",
    )
    engine = create_database_engine(settings)
    app = create_app(settings=settings, engine=engine)
    try:
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200
            assert response.text == "OK"
        assert REQUIRED_TABLES <= set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_copied_vulnerability_values_need_a_source_reference() -> None:
    """CVE and CVSS values cannot enter a finding without a tool or reference file."""
    fixture = read_fixture()
    payload = dict(fixture["finding"])
    payload["assessment_id"] = "ASM-SYNTHETIC-TEST"
    payload["asset_id"] = "AST-SYNTHETIC-TEST"
    payload["cve_ids"] = ["CVE-2026-12345"]
    payload["cvss_score"] = 7.5
    for index, evidence in enumerate(payload["evidence"]):
        evidence["raw_ref"] = {
            "tool_run_id": "TRN-SYNTHETIC-TEST",
            "json_pointer": f"/finding/evidence/{index}",
        }

    with pytest.raises(ValidationError, match="ToolRun source or reference-file citation"):
        FindingCreate.model_validate(payload)


def test_create_assessment_and_round_trip_finding_with_two_evidence_entries(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """Round-trip every common finding field and keep evidence types distinct."""
    _engine, sessions = store
    assessment, asset, created = seed_assessment_finding(sessions)
    loaded = FindingService(sessions).get(created.id)

    assert created.id == "FND-0001"
    assert loaded.id == created.id
    assert loaded.assessment_id == assessment.id
    assert loaded.title == created.title
    assert loaded.description == created.description
    assert loaded.category == "misconfig"
    assert loaded.asset_id == asset.id
    assert loaded.service_id is None
    assert loaded.port == 443
    assert loaded.protocol == "tcp"
    assert loaded.service == "Fixture HTTPS service"
    assert loaded.url == "https://fixture.invalid/"
    assert loaded.parameter is None
    assert loaded.source_tools == []
    assert loaded.raw_refs == []
    assert loaded.cve_ids == []
    assert loaded.cwe_ids == []
    assert loaded.cvss_vector is None
    assert loaded.cvss_score is None
    assert loaded.tool_severity is None
    assert loaded.confidence == "low"
    assert loaded.confidence_score == 0.25
    assert loaded.confidence_reason.startswith("SYNTHETIC TEST FIXTURE ONLY")
    assert loaded.status == "suspected"
    assert loaded.validation_status == "not_validated"
    assert loaded.risk_score is None
    assert loaded.risk_band is None
    assert loaded.risk_breakdown is None
    assert loaded.risk_rationale is None
    assert loaded.related_to == []
    assert loaded.first_seen.isoformat() == "2026-01-01T00:00:00+00:00"
    assert loaded.last_seen == loaded.first_seen
    assert loaded.created_at.tzinfo is not None
    assert [entry.type for entry in loaded.evidence] == ["observed", "inference"]
    assert loaded.evidence[0].finding_id == loaded.id
    assert loaded.evidence[1].finding_id == loaded.id
    assert all(
        entry.raw_ref is not None
        and entry.raw_ref.reference_file == "tests/fixtures/finding_roundtrip.json"
        for entry in loaded.evidence
    )
    assert loaded.evidence[0].timestamp.isoformat() == "2026-01-01T00:00:00+00:00"
    assert all("SYNTHETIC TEST FIXTURE ONLY" in entry.content for entry in loaded.evidence)


def test_finding_without_cvss_source_keeps_cvss_score_none(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """A finding with no CVSS source must persist cvss_score as null, never invented."""
    _engine, sessions = store
    _assessment, _asset, finding = seed_assessment_finding(sessions)
    assert finding.cvss_score is None
    assert finding.cvss_vector is None


def test_audit_chain_verifies_and_tamper_fails(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """Hash-chained audit events verify until a stored row is altered."""
    engine, sessions = store
    assessment, _asset, _finding = seed_assessment_finding(sessions)
    audit = AuditRepository(sessions)
    first = audit.append_audit_event(
        assessment_id=assessment.id,
        actor="system",
        event_type="assessment.created",
        detail={"name": assessment.name},
        outcome="recorded",
    )
    second = audit.append_audit_event(
        assessment_id=assessment.id,
        actor="user",
        event_type="finding.reviewed",
        detail={"finding_id": "FND-0001"},
        outcome="recorded",
    )
    assert first.seq == 1
    assert second.seq == 2
    assert second.prev_hash == first.hash
    assert audit.verify_chain(assessment.id) is True

    with engine.begin() as connection:
        connection.execute(
            update(AuditEvent).where(AuditEvent.id == first.id).values(detail={"name": "tampered"})
        )
    assert audit.verify_chain(assessment.id) is False


def test_merged_finding_keeps_per_tool_raw_references_and_sequential_ids(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """Source tool names are derived and each raw reference stays attached to its ToolRun."""
    _engine, sessions = store
    fixture = read_fixture()
    assessment = AssessmentService(sessions).create(
        AssessmentCreate.model_validate(fixture["assessment"])
    )
    asset = AssetService(sessions).create(
        AssetCreate(
            assessment_id=assessment.id,
            identifier="fixture.invalid",
            asset_type="web_application",
        )
    )
    runs = ToolRunService(sessions, Path("/unused-test-output"))
    first_run = runs.create(
        ToolRunCreate(
            assessment_id=assessment.id,
            tool="fixture-source-a",
            mode="import",
            status="skipped",
            error="SYNTHETIC TEST FIXTURE ONLY; no scanner was run.",
        )
    )
    second_run = runs.create(
        ToolRunCreate(
            assessment_id=assessment.id,
            tool="fixture-source-b",
            mode="import",
            status="skipped",
            error="SYNTHETIC TEST FIXTURE ONLY; no scanner was run.",
        )
    )

    payload = make_finding_payload(
        assessment.id,
        asset.id,
        source_refs=[
            {
                "raw_ref": {
                    "tool_run_id": run.id,
                    "reference_file": "tests/fixtures/finding_roundtrip.json",
                    "json_pointer": "/finding",
                }
            }
            for run in (first_run, second_run)
        ],
    )
    service = FindingService(sessions)

    first = service.create(payload)
    second = service.create(payload)
    loaded = service.get(first.id)

    assert first.id == "FND-0001"
    assert second.id == "FND-0002"
    assert loaded.source_tools == ["fixture-source-a", "fixture-source-b"]
    assert [source.raw_ref.tool_run_id for source in loaded.source_refs] == [
        first_run.id,
        second_run.id,
    ]
    assert all(source.raw_ref.json_pointer == "/finding" for source in loaded.source_refs)


def test_finding_rejects_a_tool_run_from_another_assessment(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """Cross-assessment source references are rejected at the repository boundary."""
    _engine, sessions = store
    assessments = AssessmentService(sessions)
    first_assessment = assessments.create(AssessmentCreate(name="First synthetic test assessment"))
    second_assessment = assessments.create(
        AssessmentCreate(name="Second synthetic test assessment")
    )
    second_asset = AssetService(sessions).create(
        AssetCreate(
            assessment_id=second_assessment.id,
            identifier="second-fixture.invalid",
            asset_type="web_application",
        )
    )
    run = ToolRunService(sessions, Path("/unused-test-output")).create(
        ToolRunCreate(
            assessment_id=first_assessment.id,
            tool="fixture-only",
            mode="import",
            status="skipped",
            error="SYNTHETIC TEST FIXTURE ONLY; no scanner was run.",
        )
    )
    payload = make_finding_payload(
        second_assessment.id,
        second_asset.id,
        source_refs=[
            {
                "raw_ref": {
                    "tool_run_id": run.id,
                    "reference_file": "tests/fixtures/finding_roundtrip.json",
                    "path": "finding",
                }
            }
        ],
    )

    with pytest.raises(InvalidRecordReference):
        FindingRepository(sessions).create(payload)


def test_finding_rejects_evidence_tool_run_from_another_assessment(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """Evidence cannot cite a ToolRun owned by a different assessment."""
    _engine, sessions = store
    assessments = AssessmentService(sessions)
    source_assessment = assessments.create(AssessmentCreate(name="Evidence source fixture"))
    target_assessment = assessments.create(AssessmentCreate(name="Finding target fixture"))
    asset = AssetService(sessions).create(
        AssetCreate(
            assessment_id=target_assessment.id,
            identifier="evidence-target.invalid",
            asset_type="web_application",
        )
    )
    run = ToolRunService(sessions, Path("/unused-test-output")).create(
        ToolRunCreate(
            assessment_id=source_assessment.id,
            tool="fixture-only",
            mode="import",
            status="skipped",
            error="SYNTHETIC TEST FIXTURE ONLY; no scanner was run.",
        )
    )
    base = make_finding_payload(target_assessment.id, asset.id)
    payload = make_finding_payload(
        target_assessment.id,
        asset.id,
        evidence=[
            {
                "type": entry.type,
                "content": entry.content,
                "timestamp": entry.timestamp,
                "raw_ref": {"tool_run_id": run.id, "json_pointer": "/synthetic"},
            }
            for entry in base.evidence
        ],
    )

    with pytest.raises(InvalidRecordReference, match="evidence tool run belongs to another"):
        FindingService(sessions).create(payload)


def test_copied_cve_must_appear_in_confined_reference_file(
    store: tuple[Engine, sessionmaker[Session]],
) -> None:
    """A citation-shaped reference cannot authorize an identifier absent from source bytes."""
    engine, sessions = store
    data_dir = Path(engine.url.database).parent / "data"
    reference_path = data_dir / "references" / "synthetic-reference.txt"
    reference_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reference_path.write_text(
        "SYNTHETIC TEST FIXTURE ONLY: CVE-2026-12345 test token, not real vulnerability claim.",
        encoding="utf-8",
    )
    fixture = read_fixture()
    assessment = AssessmentService(sessions).create(
        AssessmentCreate.model_validate(fixture["assessment"])
    )
    asset = AssetService(sessions).create(
        AssetCreate(
            assessment_id=assessment.id,
            identifier="reference-target.invalid",
            asset_type="web_application",
        )
    )

    def make_payload(identifier: str) -> FindingCreate:
        return make_finding_payload(
            assessment.id,
            asset.id,
            cve_ids=[identifier],
            evidence=[
                {
                    "type": entry.type,
                    "content": entry.content,
                    "timestamp": entry.timestamp.isoformat(),
                    "raw_ref": {
                        "reference_file": "references/synthetic-reference.txt",
                        "path": f"line/{index + 1}",
                    },
                }
                for index, entry in enumerate(
                    make_finding_payload(assessment.id, asset.id).evidence
                )
            ],
        )

    service = FindingService(sessions, data_dir)
    accepted = service.create(make_payload("CVE-2026-12345"))
    assert accepted.cve_ids == ["CVE-2026-12345"]

    with pytest.raises(InvalidRecordReference, match="absent from cited source content"):
        service.create(make_payload("CVE-2026-54321"))
