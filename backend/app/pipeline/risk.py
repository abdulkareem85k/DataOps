"""Deterministic mathematical risk scoring engine and assessment-wide re-ranking."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.models.schemas import AssetRead, FindingCreate, FindingRead
from app.repo.assets import get_asset
from app.repo.findings import list_findings, update_finding

DEFAULT_SEVERITY_BASE = {
    "critical": 95.0,
    "high": 80.0,
    "medium": 55.0,
    "low": 30.0,
    "info": 10.0,
}

CRITICALITY_MULTIPLIER = {
    "critical": 1.5,
    "high": 1.2,
    "medium": 1.0,
    "low": 0.7,
}


@dataclass(frozen=True)
class RiskAssessment:
    """Calculated risk outputs preserving full explainability."""

    score: float
    band: str
    breakdown: dict[str, Any]
    rationale: str


def score_to_band(score: float) -> str:
    """Map composite score (0-100) to priority band."""
    if score >= 85.0:
        return "P1 Critical"
    if score >= 70.0:
        return "P2 High"
    if score >= 45.0:
        return "P3 Medium"
    if score >= 20.0:
        return "P4 Low"
    return "P5 Info"


def calculate_risk(
    finding: FindingRead | FindingCreate,
    asset: AssetRead,
) -> RiskAssessment:
    """Deterministically compute composite risk score (0-100) without LLM intervention."""
    # 1. Base Score: CVSS if present from source; else tool severity fallback
    source_cvss = finding.cvss_score
    if source_cvss is not None:
        base_score = float(source_cvss) * 10.0
        cvss_label = f"CVSS {source_cvss}"
    else:
        sev_key = (finding.tool_severity or "medium").lower()
        base_score = DEFAULT_SEVERITY_BASE.get(sev_key, 50.0)
        cvss_label = "not scored by source"

    # 2. Asset Criticality (analyst adjustable)
    asset_attrs = asset.attributes or {}
    crit_label = str(asset_attrs.get("criticality", "medium")).lower()
    asset_crit = CRITICALITY_MULTIPLIER.get(crit_label, 1.0)

    # 3. Exposure Factor
    exposure_factor = 1.0
    exposure_reason = "internal / local asset"
    if asset_attrs.get("internet_facing") or asset_attrs.get("public"):
        exposure_factor = 1.25
        exposure_reason = "internet-facing asset"
    elif finding.port in (80, 443, 8080, 8443, 22):
        exposure_factor = 1.15
        exposure_reason = f"standard reachable service port {finding.port}"

    # 4. Exploitability Factor
    exploitability_factor = 1.0
    exploitability_reason = "standard vulnerability"
    title_and_desc = f"{finding.title} {finding.description}".lower()
    if any(
        k in title_and_desc
        for k in ("remote code execution", "rce", "sql injection", "sqli", "path traversal")
    ):
        exploitability_factor = 1.3
        exploitability_reason = "high-impact exploit pattern (RCE/SQLi/Traversal)"
    elif finding.cve_ids:
        exploitability_factor = 1.15
        exploitability_reason = f"known CVE identifier ({', '.join(finding.cve_ids[:2])})"
    elif finding.category == "outdated_software":
        exploitability_factor = 1.1
        exploitability_reason = "outdated component with published advisories"

    # 5. Correlation Confidence Factor
    confidence_score = float(finding.confidence_score)

    # 6. Status Multiplier (deprioritize unverified or false positives)
    st = finding.status.lower()
    if st == "false_positive":
        status_multiplier = 0.0
    elif st == "likely_false_positive":
        status_multiplier = 0.2
    elif st == "suspected":
        status_multiplier = 0.85
    else:
        status_multiplier = 1.0

    # 7. Composite Weighted Formula
    # Base score scaled by exposure, exploitability, asset criticality, and confidence
    component_weight = (
        0.4 * (base_score / 100.0) + 0.3 * (exploitability_factor / 1.3) + 0.3 * confidence_score
    )
    raw_score = (
        base_score * component_weight * (exposure_factor / 1.0) * asset_crit * status_multiplier
    )
    final_score = round(min(100.0, max(0.0, raw_score)), 1)
    band = score_to_band(final_score)

    breakdown = {
        "base_score": round(base_score, 1),
        "source_cvss": source_cvss,
        "cvss_label": cvss_label,
        "asset_criticality": asset_crit,
        "asset_criticality_label": crit_label,
        "exposure_factor": exposure_factor,
        "exposure_reason": exposure_reason,
        "exploitability_factor": exploitability_factor,
        "exploitability_reason": exploitability_reason,
        "confidence_score": round(confidence_score, 2),
        "status_multiplier": status_multiplier,
        "final_score": final_score,
        "band": band,
    }

    rationale = (
        f"Risk Score {final_score} ({band}) computed from base score {round(base_score, 1)} "
        f"({cvss_label}), asset criticality {asset_crit} ({crit_label}), "
        f"exposure factor {exposure_factor} ({exposure_reason}), "
        f"exploitability {exploitability_factor} ({exploitability_reason}), "
        f"and confidence {round(confidence_score, 2)}."
    )

    return RiskAssessment(
        score=final_score,
        band=band,
        breakdown=breakdown,
        rationale=rationale,
    )


def recalculate_assessment_risks(
    session: Session,
    assessment_id: str,
) -> list[FindingRead]:
    """Recalculate risk scores for all findings under an assessment and persist them."""
    findings = list_findings(session, assessment_id)
    updated: list[FindingRead] = []

    for f in findings:
        asset = get_asset(session, f.asset_id)
        assessment = calculate_risk(f, asset)
        up = update_finding(
            session,
            f.id,
            risk_score=assessment.score,
            risk_band=assessment.band,
            risk_breakdown=assessment.breakdown,
            risk_rationale=assessment.rationale,
        )
        updated.append(up)

    return updated
