"""Permission and immutability tests for the raw-output store."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from app.db import create_database_engine, create_session_factory, initialize_database
from app.raw_output import RawOutputError, RawOutputStore
from app.repository import InvalidRecordReference
from app.schemas import AssessmentCreate, ToolRunCreate
from app.services import AssessmentService, ToolRunService
from app.settings import Settings


def test_raw_output_is_restricted_hashed_and_never_overwritten(tmp_path: Path) -> None:
    """Stored bytes use owner-only paths, a digest, and exclusive create semantics."""
    data_dir = tmp_path / "data"
    payload = b"SYNTHETIC TEST FIXTURE ONLY; not scanner output."
    store = RawOutputStore(data_dir)

    result = store.store("ASM-TEST-0001", "TRN-TEST-0001", payload)
    output_file = data_dir / result.relative_path

    assert result.relative_path == "raw/ASM-TEST-0001/TRN-TEST-0001/raw-output.bin"
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.size_bytes == len(payload)
    assert output_file.read_bytes() == payload
    if os.name != "nt":
        assert stat.S_IMODE(output_file.stat().st_mode) == 0o400
        assert stat.S_IMODE((data_dir / "raw").stat().st_mode) == 0o700
        assert stat.S_IMODE((data_dir / "raw/ASM-TEST-0001/TRN-TEST-0001").stat().st_mode) == 0o700
    else:
        assert stat.S_IMODE(output_file.stat().st_mode) & 0o222 == 0

    with pytest.raises(RawOutputError, match="will not be overwritten"):
        store.store("ASM-TEST-0001", "TRN-TEST-0001", b"different bytes")
    assert output_file.read_bytes() == payload


def test_raw_output_rejects_path_traversal_and_oversized_content(tmp_path: Path) -> None:
    """User-controlled IDs and oversized output cannot escape or exhaust the store."""
    store = RawOutputStore(tmp_path / "data", max_bytes=3)

    with pytest.raises(RawOutputError, match="safe path identifier"):
        store.store("../outside", "TRN-TEST-0001", b"x")
    with pytest.raises(RawOutputError, match="size limit"):
        store.store("ASM-TEST-0001", "TRN-TEST-0001", b"four")


def test_tool_run_records_raw_output_path_and_digest_once(tmp_path: Path) -> None:
    """ToolRun metadata references exactly the bytes persisted by the raw store."""
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'raw-test.db'}",
        data_dir=tmp_path / "data",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    try:
        assessment = AssessmentService(sessions).create(
            AssessmentCreate(name="SYNTHETIC TEST FIXTURE ONLY")
        )
        tool_runs = ToolRunService(sessions, settings.data_dir)
        run = tool_runs.create(
            ToolRunCreate(
                assessment_id=assessment.id,
                tool="fixture-only",
                mode="import",
                status="skipped",
                error="SYNTHETIC TEST FIXTURE ONLY; no scanner was run.",
            )
        )
        content = b"SYNTHETIC TEST FIXTURE ONLY; raw store integration test."

        saved = tool_runs.store_raw_output(run.id, assessment.id, content)
        loaded = tool_runs.get(run.id)

        assert saved.sha256 == hashlib.sha256(content).hexdigest()
        assert loaded.sha256 == saved.sha256
        assert loaded.raw_output_path == saved.raw_output_path
        assert (settings.data_dir / loaded.raw_output_path).read_bytes() == content
        with pytest.raises(RawOutputError, match="already exists"):
            tool_runs.store_raw_output(run.id, assessment.id, b"overwrite attempt")
        assert tool_runs.get(run.id).sha256 == saved.sha256
    finally:
        engine.dispose()


def test_raw_output_cannot_be_stored_under_another_assessment(tmp_path: Path) -> None:
    """The service verifies ToolRun ownership before writing to disk."""
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'ownership-test.db'}",
        data_dir=tmp_path / "data",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    try:
        assessments = AssessmentService(sessions)
        owner = assessments.create(AssessmentCreate(name="SYNTHETIC TEST OWNER"))
        other = assessments.create(AssessmentCreate(name="SYNTHETIC TEST OTHER"))
        tool_runs = ToolRunService(sessions, settings.data_dir)
        run = tool_runs.create(
            ToolRunCreate(
                assessment_id=owner.id,
                tool="fixture-only",
                mode="import",
                status="skipped",
                error="SYNTHETIC TEST FIXTURE ONLY; no scanner was run.",
            )
        )

        with pytest.raises(InvalidRecordReference):
            tool_runs.store_raw_output(run.id, other.id, b"test-only bytes")
        assert tool_runs.get(run.id).raw_output_path is None
        assert not (settings.data_dir / "raw" / other.id / run.id).exists()
    finally:
        engine.dispose()
