"""Pydantic v2 Create/Read schemas. No business logic lives here."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

FindingCategory = Literal["owasp_top10", "misconfig", "outdated_software", "exposure", "other"]
EvidenceType = Literal["observed", "inference"]
ConfidenceLevel = Literal["high", "medium", "low"]
FindingStatus = Literal[
    "confirmed",
    "suspected",
    "likely_false_positive",
    "false_positive",
    "accepted_risk",
]
ValidationStatus = Literal[
    "not_validated",
    "pending_approval",
    "approved",
    "validated",
    "failed",
    "rejected",
]
ToolRunMode = Literal["live", "import"]
ToolRunStatus = Literal[
    "queued",
    "running",
    "succeeded",
    "failed",
    "timeout",
    "skipped",
    "cancelled",
]
AuditActor = Literal["user", "agent", "scope-engine", "system"]
ActionClass = Literal["discovery", "vuln_scan", "web_scan", "active_validation"]


class StrictSchema(BaseModel):
    """Shared strict schema configuration that rejects unknown input fields."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class OrmReadSchema(BaseModel):
    """Read schema base for explicitly selected ORM fields."""

    model_config = ConfigDict(from_attributes=True, extra="forbid", populate_by_name=True)


class RawReference(StrictSchema):
    """A safe locator into an immutable raw output or a local reference file."""

    tool_run_id: str | None = None
    locator: str | None = None
    reference_file: str | None = None
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    xpath: str | None = None
    json_pointer: str | None = None

    @field_validator("path", "reference_file")
    @classmethod
    def require_relative_safe_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or "\x00" in value or value.startswith(("/", "\\")):
            raise ValueError("raw reference paths must be non-empty relative paths")
        normalized = value.replace("\\", "/")
        if any(part in {".", ".."} for part in normalized.split("/")):
            raise ValueError("raw reference paths cannot contain dot segments")
        return value

    @field_validator("json_pointer")
    @classmethod
    def require_json_pointer_shape(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("/"):
            raise ValueError("JSON pointers must start with '/'")
        return value

    @model_validator(mode="after")
    def require_source_and_locator(self) -> RawReference:
        if not self.tool_run_id and not self.reference_file and not self.locator:
            raise ValueError("raw reference needs a tool_run_id, locator, or reference_file")
        if not any(
            (
                self.locator,
                self.path,
                self.line is not None,
                self.xpath,
                self.json_pointer,
            )
        ):
            raise ValueError("raw reference needs a locator, path, line, XPath, or JSON pointer")
        return self


class FindingSourceInput(StrictSchema):
    """One contributing tool run and its precise raw-output reference."""

    raw_ref: RawReference

    @model_validator(mode="after")
    def require_tool_run_reference(self) -> FindingSourceInput:
        if not self.raw_ref.tool_run_id:
            raise ValueError("per-source finding references must identify their tool_run_id")
        return self


class FindingSourceRead(StrictSchema):
    """Serialized per-source reference with the canonical tool name."""

    tool: str
    raw_ref: RawReference


class EvidenceCreate(StrictSchema):
    """Observed material or inference, stored as separate typed evidence."""

    type: EvidenceType
    content: str = Field(min_length=1, max_length=100_000)
    raw_ref: RawReference | None = None
    timestamp: AwareDatetime


class EvidenceRead(OrmReadSchema):
    id: str
    finding_id: str
    type: EvidenceType
    content: str
    raw_ref: RawReference | dict[str, Any] | None = None
    timestamp: AwareDatetime
    created_at: AwareDatetime


class AssessmentCreate(StrictSchema):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=20_000)


class AssessmentRead(OrmReadSchema):
    id: str
    name: str
    description: str | None
    created_at: AwareDatetime


class ScopeRuleCreate(StrictSchema):
    """Deterministic scope document stored for one assessment."""

    allowed_targets: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_action_classes: list[ActionClass] = Field(default_factory=list)
    rate_limit_max: int | None = Field(default=None, ge=1)
    rate_limit_window_seconds: int | None = Field(default=None, ge=1)
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    notes: str | None = Field(default=None, max_length=20_000)

    @model_validator(mode="after")
    def validate_window_and_rate(self) -> ScopeRuleCreate:
        if self.window_start and self.window_end and self.window_end < self.window_start:
            raise ValueError("window_end cannot precede window_start")
        if (self.rate_limit_max is None) ^ (self.rate_limit_window_seconds is None):
            raise ValueError("rate_limit_max and rate_limit_window_seconds must be set together")
        return self


class ScopeRuleRead(OrmReadSchema):
    id: str
    assessment_id: str
    allowed_targets: list[str]
    exclusions: list[str]
    allowed_tools: list[str]
    allowed_action_classes: list[str]
    rate_limit_max: int | None
    rate_limit_window_seconds: int | None
    window_start: AwareDatetime | None
    window_end: AwareDatetime | None
    notes: str | None
    created_at: AwareDatetime


class PlanCreate(StrictSchema):
    assessment_id: str
    title: str | None = Field(default=None, max_length=200)
    content: dict[str, Any] = Field(default_factory=dict)


class PlanStepCreate(StrictSchema):
    plan_id: str
    position: int = Field(ge=0)
    action: str = Field(min_length=1, max_length=120)
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: str | None = Field(default=None, max_length=32)


class ToolRunCreate(StrictSchema):
    assessment_id: str
    tool: str = Field(min_length=1, max_length=80)
    mode: ToolRunMode
    args: list[Any] = Field(default_factory=list)
    status: ToolRunStatus = "queued"
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    error: str | None = Field(default=None, max_length=20_000)
    source_filename: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def check_run_times(self) -> ToolRunCreate:
        if self.started_at and self.finished_at and self.finished_at < self.started_at:
            raise ValueError("finished_at cannot precede started_at")
        if self.mode == "import" and not self.source_filename:
            # Imports may omit a filename when tests only persist metadata.
            return self
        return self


class ToolRunRead(OrmReadSchema):
    id: str
    assessment_id: str
    tool: str
    mode: ToolRunMode
    args: list[Any]
    status: ToolRunStatus
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    error: str | None
    raw_output_path: str | None
    sha256: str | None
    source_filename: str | None
    created_at: AwareDatetime


class AssetCreate(StrictSchema):
    assessment_id: str
    identifier: str = Field(min_length=1, max_length=512)
    asset_type: str = Field(min_length=1, max_length=80)
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_asset_times(self) -> AssetCreate:
        if self.first_seen and self.last_seen and self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        return self


class AssetRead(OrmReadSchema):
    id: str
    assessment_id: str
    identifier: str
    asset_type: str
    attributes: dict[str, Any]
    first_seen: AwareDatetime | None
    last_seen: AwareDatetime | None
    created_at: AwareDatetime


class ServiceCreate(StrictSchema):
    asset_id: str
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    name: str | None = Field(default=None, max_length=160)
    version: str | None = Field(default=None, max_length=200)
    attributes: dict[str, Any] = Field(default_factory=dict)


class FindingCreate(StrictSchema):
    """The validated common input shape; it never calculates risk or invents IDs."""

    assessment_id: str
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=100_000)
    category: FindingCategory
    asset_id: str
    service_id: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    service: str | None = Field(
        default=None,
        max_length=160,
        validation_alias=AliasChoices("service", "service_name"),
    )
    url: str | None = Field(default=None, max_length=2_048)
    parameter: str | None = Field(default=None, max_length=512)
    source_tools: list[str] = Field(default_factory=list)
    raw_refs: list[RawReference] = Field(default_factory=list)
    source_refs: list[FindingSourceInput] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_vector: str | None = Field(default=None, max_length=256)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    tool_severity: str | None = Field(default=None, max_length=80)
    confidence: ConfidenceLevel
    confidence_score: float = Field(ge=0, le=1)
    confidence_reason: str = Field(min_length=1, max_length=20_000)
    status: FindingStatus
    validation_status: ValidationStatus
    risk_score: float | None = Field(default=None, ge=0)
    risk_band: str | None = Field(default=None, max_length=32)
    risk_breakdown: dict[str, Any] | None = None
    risk_rationale: str | None = Field(default=None, max_length=20_000)
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    related_to: list[str] = Field(default_factory=list)
    evidence: list[EvidenceCreate] = Field(min_length=1)

    @field_validator("cve_ids")
    @classmethod
    def validate_cve_shapes(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", value) for value in values):
            raise ValueError("CVE IDs must use the CVE-YYYY-NNNN format")
        return values

    @field_validator("cwe_ids")
    @classmethod
    def validate_cwe_shapes(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"CWE-\d+", value) for value in values):
            raise ValueError("CWE IDs must use the CWE-N format")
        return values

    @model_validator(mode="after")
    def enforce_temporal_and_provenance_fields(self) -> FindingCreate:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        has_source_reference = bool(self.source_refs or self.raw_refs) or any(
            item.raw_ref and item.raw_ref.reference_file for item in self.evidence
        )
        copied_fields_present = bool(
            self.cve_ids
            or self.cwe_ids
            or self.cvss_vector
            or self.cvss_score is not None
            or self.tool_severity
        )
        if copied_fields_present and not has_source_reference:
            raise ValueError(
                "CVE/CWE/CVSS/severity fields require a ToolRun source or reference-file citation"
            )
        return self


class FindingRead(OrmReadSchema):
    id: str
    assessment_id: str
    title: str
    description: str
    category: FindingCategory
    asset_id: str
    service_id: str | None
    port: int | None
    protocol: str | None
    service: str | None = None
    url: str | None
    parameter: str | None
    source_tools: list[str]
    raw_refs: list[RawReference] | list[dict[str, Any]]
    source_refs: list[FindingSourceRead] = Field(default_factory=list)
    cve_ids: list[str]
    cwe_ids: list[str]
    cvss_vector: str | None
    cvss_score: float | None
    tool_severity: str | None
    confidence: ConfidenceLevel
    confidence_score: float
    confidence_reason: str
    status: FindingStatus
    validation_status: ValidationStatus
    risk_score: float | None = None
    risk_band: str | None = None
    risk_breakdown: dict[str, Any] | None = None
    risk_rationale: str | None = None
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    related_to: list[str] = Field(default_factory=list)
    created_at: AwareDatetime
    evidence: list[EvidenceRead]


class ApprovalCreate(StrictSchema):
    assessment_id: str
    action: str = Field(min_length=1, max_length=160)
    requested_by: str | None = Field(default=None, max_length=160)
    status: str = Field(min_length=1, max_length=24)
    reason: str | None = Field(default=None, max_length=20_000)
    decided_at: AwareDatetime | None = None


class AuditEventCreate(StrictSchema):
    assessment_id: str
    actor: AuditActor
    event_type: str = Field(min_length=1, max_length=120)
    detail: dict[str, Any] = Field(default_factory=dict)
    outcome: str = Field(min_length=1, max_length=80)


class AuditEventRead(OrmReadSchema):
    id: str
    assessment_id: str
    seq: int
    timestamp: AwareDatetime
    actor: AuditActor
    event_type: str
    detail: dict[str, Any]
    outcome: str
    prev_hash: str
    hash: str
    created_at: AwareDatetime


class DecisionCreate(StrictSchema):
    assessment_id: str
    decision_type: str = Field(min_length=1, max_length=120)
    rationale: str = Field(min_length=1, max_length=20_000)
    actor: str | None = Field(default=None, max_length=160)


class ReportCreate(StrictSchema):
    assessment_id: str
    status: str = Field(min_length=1, max_length=32)
    output_path: str | None = Field(default=None, max_length=1_024)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    generated_at: AwareDatetime | None = None


class ChatMessageCreate(StrictSchema):
    assessment_id: str
    role: str = Field(min_length=1, max_length=32)
    content: str = Field(min_length=1, max_length=100_000)


class ScopeCheckRequest(StrictSchema):
    tool: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=2_048)
    action_class: ActionClass
    args: list[str] = Field(default_factory=list)
