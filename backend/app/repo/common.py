"""Shared repository helpers and errors. Routers must not import ORM models."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4


class RepositoryError(RuntimeError):
    """Base class for repository-level domain errors."""


class RecordNotFound(RepositoryError):
    """Raised when a referenced assessment, asset, service, or tool run is absent."""


class InvalidRecordReference(RepositoryError):
    """Raised when a related record belongs to another assessment."""


class ImmutableRawOutputError(RepositoryError):
    """Raised when a caller attempts to replace a ToolRun raw output reference."""


class AuditChainError(RepositoryError):
    """Raised when an audit event cannot be appended."""


def new_id(prefix: str) -> str:
    """Create an opaque, path-safe identifier for non-sequential records."""
    return f"{prefix}-{uuid4().hex}"


def as_utc(value: datetime) -> datetime:
    """Restore UTC tzinfo for SQLite DateTime values read without timezone metadata."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
