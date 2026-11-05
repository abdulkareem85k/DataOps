"""Seed helpers for Prompt 2 data-layer tests. Synthetic data only."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.models.schemas import (
    AssessmentCreate,
    AssessmentRead,
    AssetCreate,
    AssetRead,
    EvidenceCreate,
    FindingCreate,
    FindingRead,
    RawReference,
)
from app.repo.assessments import AssessmentRepository
from app.repo.assets import AssetRepository
from app.repo.findings import FindingRepository

FIXTURE_JSON = Path(__file__).parent / "fixtures" / "finding_roundtrip.json"
SYNTHETIC_TS = datetime(2026, 1, 1, tzinfo=UTC)


def seed_assessment_finding(
    sessions: sessionmaker[Session],
) -> tuple[AssessmentRead, AssetRead, FindingRead]:
    """Create one assessment, asset, and finding with observed + inference evidence."""
    assessment = AssessmentRepository(sessions).create(
        AssessmentCreate(
            name="Schema round-trip test fixture",
            description="SYNTHETIC TEST FIXTURE ONLY. Not a real assessment or scanner result.",
        )
    )
    asset = AssetRepository(sessions).create(
        AssetCreate(
            assessment_id=assessment.id,
            identifier="fixture.invalid",
            asset_type="web_application",
        )
    )
    finding = FindingRepository(sessions).create(make_finding_payload(assessment.id, asset.id))
    return assessment, asset, finding


def make_finding_payload(
    assessment_id: str,
    asset_id: str,
    **overrides: Any,
) -> FindingCreate:
    """Build a synthetic FindingCreate covering every common Prompt 2 field."""
    data: dict[str, Any] = {
        "assessment_id": assessment_id,
        "title": "Synthetic schema round-trip fixture",
        "description": (
            "SYNTHETIC TEST FIXTURE ONLY. This text tests persistence and is not a security claim."
        ),
        "category": "misconfig",
        "asset_id": asset_id,
        "port": 443,
        "protocol": "tcp",
        "service": "Fixture HTTPS service",
        "url": "https://fixture.invalid/",
        "parameter": None,
        "source_tools": [],
        "raw_refs": [],
        "cve_ids": [],
        "cwe_ids": [],
        "cvss_vector": None,
        "cvss_score": None,
        "tool_severity": None,
        "confidence": "low",
        "confidence_score": 0.25,
        "confidence_reason": "SYNTHETIC TEST FIXTURE ONLY; not an assessment conclusion.",
        "status": "suspected",
        "validation_status": "not_validated",
        "risk_score": None,
        "risk_band": None,
        "risk_breakdown": None,
        "risk_rationale": None,
        "first_seen": SYNTHETIC_TS,
        "last_seen": SYNTHETIC_TS,
        "related_to": [],
        "evidence": [
            EvidenceCreate(
                type="observed",
                content=(
                    "SYNTHETIC TEST FIXTURE ONLY: observed evidence field serialization "
                    "placeholder; not scanner output."
                ),
                raw_ref=RawReference(
                    reference_file="tests/fixtures/finding_roundtrip.json",
                    path="finding/evidence/0",
                ),
                timestamp=SYNTHETIC_TS,
            ),
            EvidenceCreate(
                type="inference",
                content=(
                    "SYNTHETIC TEST FIXTURE ONLY: inference field serialization placeholder; "
                    "not an actual inference."
                ),
                raw_ref=RawReference(
                    reference_file="tests/fixtures/finding_roundtrip.json",
                    path="finding/evidence/1",
                ),
                timestamp=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
            ),
        ],
    }
    data.update(overrides)
    if not isinstance(data.get("evidence", []), list) or (
        data.get("evidence") and isinstance(data["evidence"][0], EvidenceCreate)
    ):
        return FindingCreate.model_validate(data)
    return FindingCreate.model_validate(data)
