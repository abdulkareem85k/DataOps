"""Finding and evidence repository functions."""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload, sessionmaker

from app.models.orm import (
    Assessment,
    Asset,
    Evidence,
    Finding,
    FindingSource,
    IdCounter,
    Service,
    ToolRun,
)
from app.models.schemas import (
    EvidenceRead,
    FindingCreate,
    FindingRead,
    FindingSourceRead,
    RawReference,
)
from app.raw_output import RawOutputError, RawOutputStore
from app.repo.common import InvalidRecordReference, RecordNotFound, RepositoryError, as_utc, new_id


def create_finding(
    session: Session,
    payload: FindingCreate,
    data_dir: Path | None = None,
) -> FindingRead:
    """Allocate a sequential FND ID and commit finding, source refs, and evidence atomically."""
    assessment = session.get(Assessment, payload.assessment_id)
    if assessment is None:
        raise RecordNotFound("assessment not found")

    asset = session.get(Asset, payload.asset_id)
    if asset is None:
        raise RecordNotFound("asset not found")
    if asset.assessment_id != payload.assessment_id:
        raise InvalidRecordReference("asset belongs to another assessment")

    service: Service | None = None
    if payload.service_id is not None:
        service = session.get(Service, payload.service_id)
        if service is None:
            raise RecordNotFound("service not found")
        if service.asset_id != asset.id:
            raise InvalidRecordReference("service does not belong to the selected asset")
        if service.asset.assessment_id != payload.assessment_id:
            raise InvalidRecordReference("service belongs to another assessment")

    source_runs: list[tuple[ToolRun, FindingSource]] = []
    raw_refs = list(payload.raw_refs)
    for position, source in enumerate(payload.source_refs):
        reference = source.raw_ref
        if reference.tool_run_id is None:
            raise InvalidRecordReference("finding source must identify a ToolRun")
        tool_run = _require_tool_run(session, reference.tool_run_id, payload.assessment_id)
        source_runs.append(
            (
                tool_run,
                FindingSource(
                    id=new_id("FSR"),
                    tool_run=tool_run,
                    position=position,
                    raw_ref=reference.model_dump(mode="json"),
                ),
            )
        )
        if reference not in raw_refs:
            raw_refs.append(reference)

    for extra in payload.raw_refs:
        if extra.tool_run_id:
            _require_tool_run(session, extra.tool_run_id, payload.assessment_id)

    evidence_runs: dict[str, ToolRun] = {}
    for item in payload.evidence:
        if item.raw_ref is None or item.raw_ref.tool_run_id is None:
            continue
        evidence_run = _require_tool_run(
            session, item.raw_ref.tool_run_id, payload.assessment_id, kind="evidence"
        )
        evidence_runs[evidence_run.id] = evidence_run

    _verify_copied_values(payload, source_runs, evidence_runs, data_dir)

    counter_result = session.execute(
        update(IdCounter)
        .where(IdCounter.name == "finding")
        .values(value=IdCounter.value + 1)
        .returning(IdCounter.value)
    )
    finding_number = counter_result.scalar_one_or_none()
    if finding_number is None:
        raise RepositoryError("database schema is not initialized; finding counter is missing")

    derived_tools = list(dict.fromkeys(run.tool for run, _ in source_runs))
    source_tools = list(dict.fromkeys([*payload.source_tools, *derived_tools]))

    row = Finding(
        id=f"FND-{finding_number:04d}",
        assessment_id=payload.assessment_id,
        title=payload.title,
        description=payload.description,
        category=payload.category,
        asset=asset,
        service_row=service,
        port=payload.port,
        protocol=payload.protocol,
        service=payload.service,
        url=payload.url,
        parameter=payload.parameter,
        source_tools=source_tools,
        raw_refs=[item.model_dump(mode="json") for item in raw_refs],
        cve_ids=payload.cve_ids,
        cwe_ids=payload.cwe_ids,
        cvss_vector=payload.cvss_vector,
        cvss_score=payload.cvss_score,
        tool_severity=payload.tool_severity,
        confidence=payload.confidence,
        confidence_score=payload.confidence_score,
        confidence_reason=payload.confidence_reason,
        status=payload.status,
        validation_status=payload.validation_status,
        risk_score=payload.risk_score,
        risk_band=payload.risk_band,
        risk_breakdown=payload.risk_breakdown,
        risk_rationale=payload.risk_rationale,
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
        related_to=list(payload.related_to),
        sources=[source_row for _, source_row in source_runs],
        evidence=[
            Evidence(
                id=new_id("EVD"),
                type=item.type,
                content=item.content,
                raw_ref=item.raw_ref.model_dump(mode="json") if item.raw_ref else None,
                timestamp=item.timestamp,
            )
            for item in payload.evidence
        ],
    )
    session.add(row)
    session.flush()
    return to_finding_read(row)


def get_finding(session: Session, finding_id: str) -> FindingRead:
    """Read a finding with all source references and evidence in one repository call."""
    statement = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(
            selectinload(Finding.sources).selectinload(FindingSource.tool_run),
            selectinload(Finding.evidence),
        )
    )
    row = session.scalar(statement)
    if row is None:
        raise RecordNotFound("finding not found")
    return to_finding_read(row)


def _require_tool_run(
    session: Session,
    tool_run_id: str,
    assessment_id: str,
    kind: str = "source",
) -> ToolRun:
    tool_run = session.get(ToolRun, tool_run_id)
    if tool_run is None:
        raise RecordNotFound(f"{kind} tool run not found")
    if tool_run.assessment_id != assessment_id:
        raise InvalidRecordReference(f"{kind} tool run belongs to another assessment")
    return tool_run


def _verify_copied_values(
    payload: FindingCreate,
    source_runs: list[tuple[ToolRun, FindingSource]],
    evidence_runs: dict[str, ToolRun],
    data_dir: Path | None,
) -> None:
    """Require copied vulnerability/severity values to occur in cited source bytes."""
    values: list[tuple[str, bool]] = [
        *((value, False) for value in payload.cve_ids),
        *((value, False) for value in payload.cwe_ids),
    ]
    if payload.cvss_vector:
        values.append((payload.cvss_vector, False))
    if payload.cvss_score is not None:
        values.append((format(payload.cvss_score, "g"), True))
    if payload.tool_severity:
        values.append((payload.tool_severity, False))
    if not values:
        return
    if data_dir is None:
        raise InvalidRecordReference(
            "copied vulnerability/severity values require a configured source store"
        )

    raw_outputs = RawOutputStore(data_dir)
    runs = {run.id: run for run, _ in source_runs}
    runs.update(evidence_runs)
    source_bytes: list[bytes] = []
    for run in runs.values():
        if run.raw_output_path is None or run.sha256 is None:
            continue
        try:
            source_bytes.append(raw_outputs.read_verified(run.raw_output_path, run.sha256))
        except RawOutputError as exc:
            raise InvalidRecordReference("cited ToolRun output is unavailable or invalid") from exc

    references = [source.raw_ref for source in payload.source_refs]
    references.extend(item for item in payload.raw_refs)
    references.extend(item.raw_ref for item in payload.evidence if item.raw_ref is not None)
    for reference in references:
        if reference.reference_file is None:
            continue
        try:
            source_bytes.append(raw_outputs.read_reference_file(reference.reference_file))
        except RawOutputError as exc:
            raise InvalidRecordReference(
                "cited reference file is unavailable or outside DATA_DIR/references"
            ) from exc

    if not source_bytes:
        raise InvalidRecordReference("no cited raw output or reference-file bytes are available")
    for value, numeric in values:
        if not any(_source_contains(content, value, numeric) for content in source_bytes):
            raise InvalidRecordReference(
                "copied CVE/CWE/CVSS/severity value is absent from cited source content"
            )


def _source_contains(content: bytes, value: str, numeric: bool) -> bool:
    """Match a copied source value as a complete token in decoded untrusted text."""
    text = content.decode("utf-8", errors="replace")
    boundary = r"[0-9.]" if numeric else r"[A-Za-z0-9_-]"
    pattern = rf"(?<!{boundary}){re.escape(value)}(?!{boundary})"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def to_finding_read(row: Finding) -> FindingRead:
    """Build the public schema while preserving separate evidence/source records."""
    sources = [
        FindingSourceRead(
            tool=source.tool_run.tool,
            raw_ref=RawReference.model_validate(source.raw_ref),
        )
        for source in row.sources
    ]
    all_tools = [*(row.source_tools or []), *(item.tool for item in sources)]
    unique_tools = list(dict.fromkeys(all_tools))
    raw_refs: list[RawReference] = []
    for item in row.raw_refs or []:
        raw_refs.append(RawReference.model_validate(item))
    if not raw_refs:
        raw_refs = [item.raw_ref for item in sources]
    evidence = [
        EvidenceRead(
            id=item.id,
            finding_id=item.finding_id,
            type=item.type,  # type: ignore[arg-type]
            content=item.content,
            raw_ref=RawReference.model_validate(item.raw_ref) if item.raw_ref else None,
            timestamp=as_utc(item.timestamp),
            created_at=as_utc(item.created_at),
        )
        for item in sorted(row.evidence, key=lambda item: (item.timestamp, item.id))
    ]
    return FindingRead(
        id=row.id,
        assessment_id=row.assessment_id,
        title=row.title,
        description=row.description,
        category=row.category,  # type: ignore[arg-type]
        asset_id=row.asset_id,
        service_id=row.service_id,
        port=row.port,
        protocol=row.protocol,
        service=row.service,
        url=row.url,
        parameter=row.parameter,
        source_tools=unique_tools,
        raw_refs=raw_refs,
        source_refs=sources,
        cve_ids=list(row.cve_ids or []),
        cwe_ids=list(row.cwe_ids or []),
        cvss_vector=row.cvss_vector,
        cvss_score=row.cvss_score,
        tool_severity=row.tool_severity,
        confidence=row.confidence,  # type: ignore[arg-type]
        confidence_score=row.confidence_score,
        confidence_reason=row.confidence_reason,
        status=row.status,  # type: ignore[arg-type]
        validation_status=row.validation_status,  # type: ignore[arg-type]
        risk_score=row.risk_score,
        risk_band=row.risk_band,
        risk_breakdown=row.risk_breakdown,
        risk_rationale=row.risk_rationale,
        first_seen=as_utc(row.first_seen),
        last_seen=as_utc(row.last_seen),
        related_to=list(row.related_to or []),
        created_at=as_utc(row.created_at),
        evidence=evidence,
    )


class FindingRepository:
    """Session-factory wrapper used by existing services."""

    def __init__(self, sessions: sessionmaker[Session], data_dir: Path | None = None) -> None:
        self.sessions = sessions
        self.data_dir = data_dir

    def create(self, payload: FindingCreate) -> FindingRead:
        with self.sessions.begin() as session:
            return create_finding(session, payload, self.data_dir)

    def get(self, finding_id: str) -> FindingRead:
        with self.sessions() as session:
            return get_finding(session, finding_id)
