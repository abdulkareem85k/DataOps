"""ToolRun repository functions."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.models.orm import Assessment, ToolRun
from app.models.schemas import ToolRunCreate, ToolRunRead
from app.raw_output import StoredRawOutput
from app.repo.common import ImmutableRawOutputError, RecordNotFound, as_utc, new_id


def create_tool_run(session: Session, payload: ToolRunCreate) -> ToolRunRead:
    """Persist ToolRun metadata without executing a scanner."""
    if session.get(Assessment, payload.assessment_id) is None:
        raise RecordNotFound("assessment not found")
    row = ToolRun(
        id=new_id("TRN"),
        assessment_id=payload.assessment_id,
        tool=payload.tool,
        mode=payload.mode,
        args=list(payload.args),
        status=payload.status,
        started_at=payload.started_at,
        finished_at=payload.finished_at,
        error=payload.error,
        source_filename=payload.source_filename,
    )
    session.add(row)
    session.flush()
    return to_tool_run_read(row)


def get_tool_run(session: Session, tool_run_id: str) -> ToolRunRead:
    """Read one ToolRun record."""
    row = session.get(ToolRun, tool_run_id)
    if row is None:
        raise RecordNotFound("tool run not found")
    return to_tool_run_read(row)


def attach_tool_run_raw_output(
    session: Session, tool_run_id: str, stored: StoredRawOutput
) -> ToolRunRead:
    """Link write-once raw output metadata to a ToolRun without changing its file."""
    row = session.get(ToolRun, tool_run_id)
    if row is None:
        raise RecordNotFound("tool run not found")
    if row.raw_output_path is not None or row.sha256 is not None:
        raise ImmutableRawOutputError("a ToolRun raw output reference cannot be replaced")
    row.raw_output_path = stored.relative_path
    row.sha256 = stored.sha256
    session.flush()
    return to_tool_run_read(row)


def to_tool_run_read(row: ToolRun) -> ToolRunRead:
    """Convert a ToolRun row to a stable UTC-aware read schema."""
    return ToolRunRead(
        id=row.id,
        assessment_id=row.assessment_id,
        tool=row.tool,
        mode=row.mode,
        args=list(row.args or []),
        status=row.status,
        started_at=as_utc(row.started_at) if row.started_at else None,
        finished_at=as_utc(row.finished_at) if row.finished_at else None,
        error=row.error,
        raw_output_path=row.raw_output_path,
        sha256=row.sha256,
        source_filename=row.source_filename,
        created_at=as_utc(row.created_at),
    )


class ToolRunRepository:
    """Session-factory wrapper used by existing services."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def create(self, payload: ToolRunCreate) -> ToolRunRead:
        with self.sessions.begin() as session:
            return create_tool_run(session, payload)

    def get(self, tool_run_id: str) -> ToolRunRead:
        with self.sessions() as session:
            return get_tool_run(session, tool_run_id)

    def attach_raw_output(self, tool_run_id: str, stored: StoredRawOutput) -> ToolRunRead:
        with self.sessions.begin() as session:
            return attach_tool_run_raw_output(session, tool_run_id, stored)
