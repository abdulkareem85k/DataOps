"""SQLAlchemy models for the VAPT assessment and evidence data layer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    """Return an aware UTC timestamp for application-created records."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for the application's SQLite schema."""


class Assessment(Base):
    """An authorized security assessment workspace."""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    plans: Mapped[list[Plan]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    tool_runs: Mapped[list[ToolRun]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    approvals: Mapped[list[Approval]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    decisions: Mapped[list[Decision]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    chat_messages: Mapped[list[ChatMessage]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class ScopeRule(Base):
    """Persisted deterministic scope document for one assessment."""

    __tablename__ = "scope_rules"
    __table_args__ = (UniqueConstraint("assessment_id", name="uq_scope_rule_assessment"),)

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    allowed_targets: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    exclusions: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    allowed_tools: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    allowed_action_classes: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    rate_limit_max: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="scope_rules")


class Plan(Base):
    """An assessment plan record."""

    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="plans")
    steps: Mapped[list[PlanStep]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class PlanStep(Base):
    """A step belonging to a stored plan."""

    __tablename__ = "plan_steps"
    __table_args__ = (UniqueConstraint("plan_id", "position", name="uq_plan_step_position"),)

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    plan_id: Mapped[str] = mapped_column(ForeignKey("plans.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    plan: Mapped[Plan] = relationship(back_populates="steps")


class ToolRun(Base):
    """A scanner invocation or imported tool result with immutable-output metadata."""

    __tablename__ = "tool_runs"
    __table_args__ = (
        CheckConstraint("mode IN ('live', 'import')", name="ck_tool_run_mode"),
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', "
            "'failed', 'timeout', 'skipped', 'cancelled')",
            name="ck_tool_run_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    tool: Mapped[str] = mapped_column(String(80), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    args: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="tool_runs")
    finding_sources: Mapped[list[FindingSource]] = relationship(back_populates="tool_run")


class Asset(Base):
    """An assessed host, web application, or other scoped asset."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("assessment_id", "identifier", name="uq_asset_assessment_identifier"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(80), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="assets")
    services: Mapped[list[Service]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="asset")


class Service(Base):
    """A network or web service observed on an asset."""

    __tablename__ = "services"
    __table_args__ = (
        CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)", name="ck_service_port"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    asset: Mapped[Asset] = relationship(back_populates="services")
    findings: Mapped[list[Finding]] = relationship(back_populates="service_row")


class Finding(Base):
    """A common, provenance-preserving security finding."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("assessment_id", "id", name="uq_finding_assessment_id"),
        CheckConstraint(
            "category IN ('owasp_top10', 'misconfig', 'outdated_software', 'exposure', 'other')",
            name="ck_finding_category",
        ),
        CheckConstraint("confidence IN ('high', 'medium', 'low')", name="ck_finding_confidence"),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 1", name="ck_finding_confidence_score"
        ),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_finding_cvss_score",
        ),
        CheckConstraint(
            "status IN ('confirmed', 'suspected', 'likely_false_positive', "
            "'false_positive', 'accepted_risk')",
            name="ck_finding_status",
        ),
        CheckConstraint(
            "validation_status IN ('not_validated', 'pending_approval', "
            "'approved', 'validated', 'failed', 'rejected')",
            name="ck_finding_validation_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    service_id: Mapped[str | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL"), nullable=True, index=True
    )
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    service: Mapped[str | None] = mapped_column(String(160), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_tools: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    raw_refs: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    tool_severity: Mapped[str | None] = mapped_column(String(80), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_band: Mapped[str | None] = mapped_column(String(32), nullable=True)
    risk_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    risk_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    related_to: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")
    asset: Mapped[Asset] = relationship(back_populates="findings")
    service_row: Mapped[Service | None] = relationship(back_populates="findings")
    sources: Mapped[list[FindingSource]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingSource.position"
    )
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingSource(Base):
    """A normalized per-tool source reference for a merged finding."""

    __tablename__ = "finding_sources"
    __table_args__ = (
        UniqueConstraint("finding_id", "position", name="uq_finding_source_position"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    tool_run_id: Mapped[str] = mapped_column(
        ForeignKey("tool_runs.id", ondelete="RESTRICT"), index=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_ref: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="sources")
    tool_run: Mapped[ToolRun] = relationship(back_populates="finding_sources")


class Evidence(Base):
    """Observed evidence or an explicitly separate inference attached to a finding."""

    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint("type IN ('observed', 'inference')", name="ck_evidence_type"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    raw_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class Approval(Base):
    """A persisted human approval decision; no approval workflow is implied by this table alone."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(160), nullable=False)
    requested_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assessment: Mapped[Assessment] = relationship(back_populates="approvals")


class AuditEvent(Base):
    """Append-only, hash-chained audit event. Never updated or deleted by application code."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("assessment_id", "seq", name="uq_audit_event_assessment_seq"),
        CheckConstraint(
            "actor IN ('user', 'agent', 'scope-engine', 'system')",
            name="ck_audit_event_actor",
        ),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    actor: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    outcome: Mapped[str] = mapped_column(String(80), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column("hash", String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="audit_events")


class Decision(Base):
    """A recorded analyst or system decision for an assessment."""

    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    decision_type: Mapped[str] = mapped_column(String(120), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="decisions")


class Report(Base):
    """A report artifact record; no report generation is implied by this model."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    output_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assessment: Mapped[Assessment] = relationship(back_populates="reports")


class ChatMessage(Base):
    """A conversational message associated with an assessment."""

    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    assessment: Mapped[Assessment] = relationship(back_populates="chat_messages")


class IdCounter(Base):
    """Small database-backed counter for sequential human-readable finding IDs."""

    __tablename__ = "id_counters"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
