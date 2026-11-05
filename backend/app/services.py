"""Application services coordinating repositories and raw-output storage."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from app.models.schemas import (
    AssessmentCreate,
    AssessmentRead,
    AssetCreate,
    AssetRead,
    FindingCreate,
    FindingRead,
    ToolRunCreate,
    ToolRunRead,
)
from app.raw_output import RawOutputStore
from app.repo.assessments import AssessmentRepository
from app.repo.assets import AssetRepository
from app.repo.common import InvalidRecordReference
from app.repo.findings import FindingRepository
from app.repo.tool_runs import ToolRunRepository


class AssessmentService:
    """Use-case boundary for assessment records."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.repository = AssessmentRepository(sessions)

    def create(self, payload: AssessmentCreate) -> AssessmentRead:
        """Create an assessment with no generated assets or findings."""
        return self.repository.create(payload)

    def get(self, assessment_id: str) -> AssessmentRead:
        """Read one assessment."""
        return self.repository.get(assessment_id)


class AssetService:
    """Use-case boundary for assessment-owned assets."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.repository = AssetRepository(sessions)

    def create(self, payload: AssetCreate) -> AssetRead:
        """Persist one asset under an existing assessment."""
        return self.repository.create(payload)

    def get(self, asset_id: str) -> AssetRead:
        """Read one asset."""
        return self.repository.get(asset_id)


class ToolRunService:
    """Use-case boundary for ToolRuns and their write-once raw outputs."""

    def __init__(self, sessions: sessionmaker[Session], data_dir: Path) -> None:
        self.repository = ToolRunRepository(sessions)
        self.raw_outputs = RawOutputStore(data_dir)

    def create(self, payload: ToolRunCreate) -> ToolRunRead:
        """Create metadata for a queued/live/imported run without executing a tool."""
        return self.repository.create(payload)

    def get(self, tool_run_id: str) -> ToolRunRead:
        """Read a ToolRun and its raw-output metadata."""
        return self.repository.get(tool_run_id)

    def store_raw_output(self, tool_run_id: str, assessment_id: str, content: bytes) -> ToolRunRead:
        """Store bytes once, hash them, then attach the immutable metadata to the ToolRun."""
        run = self.repository.get(tool_run_id)
        if run.assessment_id != assessment_id:
            raise InvalidRecordReference("tool run belongs to another assessment")
        stored = self.raw_outputs.store(assessment_id, tool_run_id, content)
        return self.repository.attach_raw_output(tool_run_id, stored)


class FindingService:
    """Use-case boundary for provenance-backed Finding creation and retrieval."""

    def __init__(self, sessions: sessionmaker[Session], data_dir: Path | None = None) -> None:
        self.repository = FindingRepository(sessions, data_dir)

    def create(self, payload: FindingCreate) -> FindingRead:
        """Create a validated finding and its independent source/evidence records."""
        return self.repository.create(payload)

    def get(self, finding_id: str) -> FindingRead:
        """Retrieve all finding fields, per-tool sources, and typed evidence."""
        return self.repository.get(finding_id)
