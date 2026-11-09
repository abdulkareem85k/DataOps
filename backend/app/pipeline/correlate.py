"""Cross-tool finding deduplication, corroboration, and false-positive heuristics."""

from __future__ import annotations

import difflib

from app.models.schemas import (
    ConfidenceLevel,
    FindingCreate,
    FindingSourceInput,
    FindingStatus,
    RawReference,
)

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CATEGORY_PRIORITY = ["owasp_top10", "outdated_software", "misconfig", "exposure", "other"]

STATIC_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".txt",
    "/icons/readme",
    "/icons/readme.html",
    "/icons/",
)


def _should_merge(f1: FindingCreate, f2: FindingCreate) -> bool:
    """Determine whether two findings on the same asset and port represent the same issue."""
    if f1.asset_id != f2.asset_id:
        return False
    if f1.port != f2.port:
        return False
    if f1.protocol != f2.protocol:
        return False

    # 1. Common CVE
    if f1.cve_ids and f2.cve_ids and (set(f1.cve_ids) & set(f2.cve_ids)):
        return True

    # 2. Common CWE on same URL/param
    if f1.cwe_ids and f2.cwe_ids and (set(f1.cwe_ids) & set(f2.cwe_ids)):
        if (f1.url or "") == (f2.url or "") and (f1.parameter or "") == (f2.parameter or ""):
            return True

    # 3. Text title similarity threshold >= 0.85
    ratio = difflib.SequenceMatcher(None, f1.title.lower(), f2.title.lower()).ratio()
    if ratio >= 0.85:
        return True

    return False


def _merge_two_findings(f1: FindingCreate, f2: FindingCreate) -> FindingCreate:
    """Merge two matching findings into one while preserving all provenance and evidence."""
    # Source tools
    all_tools = sorted(set(f1.source_tools + f2.source_tools))

    # Raw references
    seen_raw = set()
    raw_refs: list[RawReference] = []
    for r in f1.raw_refs + f2.raw_refs:
        key = (r.tool_run_id, r.locator, r.path, r.xpath, r.json_pointer)
        if key not in seen_raw:
            seen_raw.add(key)
            raw_refs.append(r)

    # Source references
    seen_sources = set()
    source_refs: list[FindingSourceInput] = []
    for s in f1.source_refs + f2.source_refs:
        key = (
            s.raw_ref.tool_run_id,
            s.raw_ref.locator,
            s.raw_ref.path,
            s.raw_ref.xpath,
            s.raw_ref.json_pointer,
        )
        if key not in seen_sources:
            seen_sources.add(key)
            source_refs.append(s)

    # CVE and CWE IDs
    all_cves = sorted(set(f1.cve_ids + f2.cve_ids))
    all_cwes = sorted(set(f1.cwe_ids + f2.cwe_ids))

    # Evidence
    evidence_list = list(f1.evidence) + list(f2.evidence)

    # Severity: highest
    sev1 = (f1.tool_severity or "info").lower()
    sev2 = (f2.tool_severity or "info").lower()
    tool_sev = sev1 if SEVERITY_ORDER.get(sev1, 1) >= SEVERITY_ORDER.get(sev2, 1) else sev2

    # Category: highest priority
    cat = f1.category
    for candidate in CATEGORY_PRIORITY:
        if candidate in (f1.category, f2.category):
            cat = candidate  # type: ignore
            break

    # Title & Description: prefer longer / more descriptive
    title = f1.title if len(f1.title) >= len(f2.title) else f2.title
    desc = f1.description if len(f1.description) >= len(f2.description) else f2.description

    # CVSS
    cvss_score = max(
        (s for s in (f1.cvss_score, f2.cvss_score) if s is not None),
        default=None,
    )
    cvss_vector = f1.cvss_vector or f2.cvss_vector

    # Temporal
    first_seen = min(f1.first_seen, f2.first_seen)
    last_seen = max(f1.last_seen, f2.last_seen)

    # Base confidence
    confidence_score = max(f1.confidence_score, f2.confidence_score)
    confidence: ConfidenceLevel = (
        "high" if confidence_score >= 0.8 else ("medium" if confidence_score >= 0.5 else "low")
    )
    confidence_reason = (
        f1.confidence_reason if confidence_score == f1.confidence_score else f2.confidence_reason
    )

    # Status
    status = f1.status
    if "confirmed" in (f1.status, f2.status):
        status = "confirmed"

    return FindingCreate(
        assessment_id=f1.assessment_id,
        title=title,
        description=desc,
        category=cat,
        asset_id=f1.asset_id,
        service_id=f1.service_id or f2.service_id,
        port=f1.port,
        protocol=f1.protocol,
        service=f1.service or f2.service,
        url=f1.url or f2.url,
        parameter=f1.parameter or f2.parameter,
        source_tools=all_tools,
        raw_refs=raw_refs,
        source_refs=source_refs,
        cve_ids=all_cves,
        cwe_ids=all_cwes,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        tool_severity=tool_sev,
        confidence=confidence,
        confidence_score=confidence_score,
        confidence_reason=confidence_reason,
        status=status,
        validation_status="not_validated",
        first_seen=first_seen,
        last_seen=last_seen,
        related_to=[],
        evidence=evidence_list,
    )


def apply_corroboration_and_heuristics(
    finding: FindingCreate,
    service_banners: dict[tuple[str, int], str] | None = None,
) -> FindingCreate:
    """Boost multi-tool findings and apply explainable false-positive heuristics."""
    # 1. Multi-tool corroboration boost
    if len(finding.source_tools) >= 2:
        boosted_score = min(1.0, finding.confidence_score + 0.15)
        conf_level: ConfidenceLevel = "high" if boosted_score >= 0.8 else "medium"
        tools_str = ", ".join(sorted(finding.source_tools))
        reason = f"Corroborated by {len(finding.source_tools)} independent tools ({tools_str})"
        finding = finding.model_copy(
            update={
                "confidence_score": boosted_score,
                "confidence": conf_level,
                "confidence_reason": reason,
            }
        )

    # 2. Heuristic: Missing security headers on purely static assets
    title_lower = finding.title.lower()
    desc_lower = finding.description.lower()
    is_header_finding = any(
        k in title_lower or k in desc_lower
        for k in (
            "x-frame-options",
            "content-security-policy",
            "strict-transport-security",
            "clickjacking",
            "anti-clickjacking",
            "missing header",
            "header is not present",
        )
    )

    if is_header_finding and finding.url:
        url_lower = finding.url.lower()
        if any(url_lower.endswith(ext) or ext in url_lower for ext in STATIC_EXTENSIONS):
            status: FindingStatus = "likely_false_positive"
            reason = (
                f"{finding.confidence_reason} [Heuristic: flagged as likely false positive "
                f"because missing security header is reported on static asset {finding.url}]"
            )
            finding = finding.model_copy(update={"status": status, "confidence_reason": reason})

    # 3. Heuristic: Service banner contradiction
    if service_banners and finding.port is not None:
        key = (finding.asset_id, finding.port)
        banner = service_banners.get(key)
        if banner:
            # Check for version contradiction (e.g. Apache 2.2 vs 2.4.41)
            b_lower = banner.lower()
            if "apache/2.4" in b_lower and any("2.2." in c or "2.0." in c for c in finding.cve_ids):
                status = "likely_false_positive"
                new_score = max(0.1, finding.confidence_score - 0.3)
                reason = (
                    f"{finding.confidence_reason} [Heuristic: banner '{banner}' "
                    f"contradicts older version target of reported vulnerability]"
                )
                finding = finding.model_copy(
                    update={
                        "status": status,
                        "confidence_score": new_score,
                        "confidence_reason": reason,
                    }
                )

    return finding


def correlate_findings(
    findings: list[FindingCreate],
    service_banners: dict[tuple[str, int], str] | None = None,
) -> list[FindingCreate]:
    """Deduplicate findings on the same asset/port, corroborate multi-tool findings,
    and link cross-host duplicates.
    """
    if not findings:
        return []

    merged_pool: list[FindingCreate] = []

    for finding in findings:
        matched_idx = -1
        for idx, existing in enumerate(merged_pool):
            if _should_merge(existing, finding):
                matched_idx = idx
                break

        if matched_idx >= 0:
            merged_pool[matched_idx] = _merge_two_findings(merged_pool[matched_idx], finding)
        else:
            merged_pool.append(finding)

    # Apply corroboration boosts and explainable false-positive heuristics
    final_findings: list[FindingCreate] = [
        apply_corroboration_and_heuristics(f, service_banners) for f in merged_pool
    ]

    # Link related findings across separate hosts (never merge across separate assets)
    for i, f1 in enumerate(final_findings):
        related: list[str] = list(f1.related_to)
        for j, f2 in enumerate(final_findings):
            if i != j and f1.asset_id != f2.asset_id:
                # Same CVE on different host
                if f1.cve_ids and f2.cve_ids and (set(f1.cve_ids) & set(f2.cve_ids)):
                    cve_str = ",".join(sorted(set(f1.cve_ids) & set(f2.cve_ids)))
                    link_desc = f"asset:{f2.asset_id}:cve:{cve_str}"
                    if link_desc not in related:
                        related.append(link_desc)
        if related != f1.related_to:
            final_findings[i] = f1.model_copy(update={"related_to": related})

    return final_findings
