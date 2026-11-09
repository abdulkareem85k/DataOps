"""Normalize raw observations into the unified FindingCreate schema."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.schemas import (
    ConfidenceLevel,
    EvidenceCreate,
    FindingCategory,
    FindingCreate,
    FindingSourceInput,
    FindingStatus,
    RawObservation,
    RawReference,
    ValidationStatus,
)
from app.repo.assets import get_or_create_asset, get_or_create_service

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_PATTERN = re.compile(r"^CWE-\d+$")

VALID_CATEGORIES: set[str] = {"owasp_top10", "misconfig", "outdated_software", "exposure", "other"}
VALID_CONFIDENCES: set[str] = {"high", "medium", "low"}


def utc_now() -> datetime:
    return datetime.now(UTC)


def normalize_observation(
    session: Session,
    assessment_id: str,
    obs: RawObservation,
) -> FindingCreate:
    """Transform one scanner RawObservation into a validated FindingCreate model."""
    # 1. Resolve or create asset
    asset = get_or_create_asset(
        session,
        assessment_id=assessment_id,
        identifier=obs.asset_identifier,
        asset_type=obs.asset_type,
    )

    # 2. Resolve service if port is specified
    service_id: str | None = None
    if obs.port is not None:
        service = get_or_create_service(
            session,
            asset_id=asset.id,
            port=obs.port,
            protocol=obs.protocol,
            name=obs.service_name,
            version=obs.service_version,
        )
        service_id = service.id

    # 3. Clean and validate category
    cat_val = obs.category.lower() if obs.category else "misconfig"
    if cat_val not in VALID_CATEGORIES:
        cat_val = "misconfig"
    category: FindingCategory = cat_val  # type: ignore

    # 4. Clean and validate confidence
    conf_val = obs.confidence.lower() if obs.confidence else "medium"
    if conf_val not in VALID_CONFIDENCES:
        conf_val = "medium"
    confidence: ConfidenceLevel = conf_val  # type: ignore
    confidence_score = float(max(0.0, min(1.0, obs.confidence_score)))

    # 5. Extract strict CVE and CWE IDs
    valid_cves = [c.upper() for c in obs.cve_ids if CVE_PATTERN.match(c.upper())]
    valid_cwes = [c.upper() for c in obs.cwe_ids if CWE_PATTERN.match(c.upper())]

    # 6. Ensure compliant RawReference
    raw_dict = dict(obs.raw_ref)
    run_id = raw_dict.get("tool_run_id") or "TRN-unknown"
    raw_dict["tool_run_id"] = run_id
    if not any(k in raw_dict for k in ("locator", "path", "line", "xpath", "json_pointer")):
        raw_dict["locator"] = f"{obs.tool}:{obs.asset_identifier}:{obs.port or 0}"

    raw_reference = RawReference(**raw_dict)
    source_ref = FindingSourceInput(raw_ref=raw_reference)

    # 7. Wrap evidence
    obs_timestamp = obs.timestamp or utc_now()
    evidence_item = EvidenceCreate(
        type="observed",
        content=(obs.evidence or obs.description)[:100_000],
        raw_ref=raw_reference,
        timestamp=obs_timestamp,
    )

    # 8. Initial status
    status: FindingStatus = (
        "confirmed"
        if confidence == "high" and obs.severity in ("critical", "high")
        else "suspected"
    )
    validation_status: ValidationStatus = "not_validated"

    return FindingCreate(
        assessment_id=assessment_id,
        title=obs.title[:300],
        description=obs.description[:100_000],
        category=category,
        asset_id=asset.id,
        service_id=service_id,
        port=obs.port,
        protocol=obs.protocol,
        service=obs.service_name,
        url=obs.url[:2048] if obs.url else None,
        parameter=obs.parameter[:512] if obs.parameter else None,
        source_tools=[obs.tool],
        raw_refs=[raw_reference],
        source_refs=[source_ref],
        cve_ids=valid_cves,
        cwe_ids=valid_cwes,
        cvss_vector=obs.cvss_vector,
        cvss_score=obs.cvss_score,
        tool_severity=obs.severity,
        confidence=confidence,
        confidence_score=confidence_score,
        confidence_reason=f"Observed directly by {obs.tool}",
        status=status,
        validation_status=validation_status,
        first_seen=obs_timestamp,
        last_seen=obs_timestamp,
        related_to=[],
        evidence=[evidence_item],
    )
