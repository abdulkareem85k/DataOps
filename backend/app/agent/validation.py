"""Input sanitization and anti-hallucination guardrails for LLM responses."""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from app.repo.findings import list_findings

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def wrap_untrusted_input(content: str) -> str:
    """Wrap raw scanner output or target payload in strict untrusted tags."""
    sanitized = content.replace("<untrusted_scanner_output>", "").replace(
        "</untrusted_scanner_output>", ""
    )
    return f"<untrusted_scanner_output>\n{sanitized}\n</untrusted_scanner_output>"


def validate_grounding(
    session: Session,
    assessment_id: str,
    text: str,
) -> tuple[str, list[str]]:
    """Verify that every CVE/CWE mentioned in the model output exists in stored findings.

    Removes or flags ungrounded identifiers to prevent AI hallucination.
    """
    findings = list_findings(session, assessment_id)
    grounded_cves: set[str] = set()
    grounded_cwes: set[str] = set()

    for f in findings:
        for cve in f.cve_ids:
            grounded_cves.add(cve.upper())
        for cwe in f.cwe_ids:
            grounded_cwes.add(cwe.upper())

    hallucinations: list[str] = []
    cleaned_text = text

    # Check CVEs
    mentioned_cves = set(CVE_PATTERN.findall(text))
    for cve in mentioned_cves:
        upper_cve = cve.upper()
        if upper_cve not in grounded_cves:
            hallucinations.append(upper_cve)
            # Replace hallucinated CVE with warning tag
            cleaned_text = re.sub(
                rf"\b{re.escape(cve)}\b",
                f"[UNGROUNDED_CLAIM: {upper_cve} not in assessment findings]",
                cleaned_text,
            )

    # Check CWEs
    mentioned_cwes = set(CWE_PATTERN.findall(text))
    for cwe in mentioned_cwes:
        upper_cwe = cwe.upper()
        if upper_cwe not in grounded_cwes:
            hallucinations.append(upper_cwe)
            cleaned_text = re.sub(
                rf"\b{re.escape(cwe)}\b",
                f"[UNGROUNDED_CLAIM: {upper_cwe} not in assessment findings]",
                cleaned_text,
            )

    return cleaned_text, hallucinations
