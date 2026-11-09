"""Repository functions. Routers must not touch the ORM directly."""

from app.repo.assessments import AssessmentRepository, create_assessment, get_assessment
from app.repo.assets import (
    AssetRepository,
    create_asset,
    create_service,
    get_asset,
    get_or_create_asset,
    get_or_create_service,
    get_service,
    list_assets,
    list_services,
)
from app.repo.audit import append_audit_event, verify_chain
from app.repo.common import (
    ImmutableRawOutputError,
    InvalidRecordReference,
    RecordNotFound,
    RepositoryError,
)
from app.repo.findings import (
    FindingRepository,
    create_finding,
    get_finding,
    get_findings_summary,
    list_findings,
    update_finding,
)
from app.repo.scope import get_scope_rules, upsert_scope_rules
from app.repo.tool_runs import (
    ToolRunRepository,
    attach_tool_run_raw_output,
    create_tool_run,
    get_tool_run,
    list_tool_runs,
    update_tool_run,
)

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
    "attach_tool_run_raw_output",
    "create_assessment",
    "create_asset",
    "create_finding",
    "create_service",
    "create_tool_run",
    "get_assessment",
    "get_asset",
    "get_finding",
    "get_findings_summary",
    "get_or_create_asset",
    "get_or_create_service",
    "get_scope_rules",
    "get_service",
    "get_tool_run",
    "list_assets",
    "list_findings",
    "list_services",
    "list_tool_runs",
    "update_finding",
    "update_tool_run",
    "upsert_scope_rules",
    "verify_chain",
]
