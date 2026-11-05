"""Compatibility re-export of repository types used by existing services."""

from app.repo.assessments import AssessmentRepository
from app.repo.assets import AssetRepository
from app.repo.common import (
    ImmutableRawOutputError,
    InvalidRecordReference,
    RecordNotFound,
    RepositoryError,
)
from app.repo.findings import FindingRepository
from app.repo.tool_runs import ToolRunRepository

__all__ = [
    "AssessmentRepository",
    "AssetRepository",
    "FindingRepository",
    "ImmutableRawOutputError",
    "InvalidRecordReference",
    "RecordNotFound",
    "RepositoryError",
    "ToolRunRepository",
]
