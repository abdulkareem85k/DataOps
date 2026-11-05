"""Repository functions. Routers must not touch the ORM directly."""

from app.repo.assessments import AssessmentRepository, create_assessment, get_assessment
from app.repo.assets import AssetRepository, create_asset, get_asset
from app.repo.audit import append_audit_event, verify_chain
from app.repo.common import (
    ImmutableRawOutputError,
    InvalidRecordReference,
    RecordNotFound,
    RepositoryError,
)
from app.repo.findings import FindingRepository, create_finding, get_finding
from app.repo.scope import get_scope_rules, upsert_scope_rules
from app.repo.tool_runs import ToolRunRepository, create_tool_run, get_tool_run

__all__ = [
    "AssessmentRepository",
    "AssetRepository",
    "FindingRepository",
    "ImmutableRawOutputError",
    "InvalidRecordReference",
    "RecordNotFound",
    "RepositoryError",
    "ToolRunRepository",
    "append_audit_event",
    "create_assessment",
    "create_asset",
    "create_finding",
    "create_tool_run",
    "get_assessment",
    "get_asset",
    "get_finding",
    "get_scope_rules",
    "get_tool_run",
    "upsert_scope_rules",
    "verify_chain",
]
