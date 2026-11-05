"""Restricted, immutable-on-write storage for raw scanner/import outputs."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024


class RawOutputError(ValueError):
    """Raised when a raw output cannot be stored or read safely."""


@dataclass(frozen=True)
class StoredRawOutput:
    """Write-once output metadata persisted on the associated ToolRun."""

    relative_path: str
    sha256: str
    size_bytes: int


class RawOutputStore:
    """Store bytes below DATA_DIR/raw without overwriting existing output files."""

    def __init__(self, data_dir: Path, max_bytes: int = _DEFAULT_MAX_BYTES) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.data_dir = data_dir.expanduser().resolve()
        self.max_bytes = max_bytes

    @staticmethod
    def _validate_identifier(value: str, field_name: str) -> None:
        if not _ID_PATTERN.fullmatch(value):
            raise RawOutputError(f"{field_name} is not a safe path identifier")

    @staticmethod
    def _secure_directory(path: Path) -> None:
        if path.is_symlink():
            raise RawOutputError("symlinks are not allowed in raw-output directories")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise RawOutputError("symlinks are not allowed in raw-output directories")
        os.chmod(path, 0o700)

    def store(self, assessment_id: str, tool_run_id: str, content: bytes) -> StoredRawOutput:
        """Create one immutable output file using exclusive creation and restricted modes."""
        self._validate_identifier(assessment_id, "assessment_id")
        self._validate_identifier(tool_run_id, "tool_run_id")
        if not isinstance(content, bytes):
            raise RawOutputError("raw output must be provided as bytes")
        if len(content) > self.max_bytes:
            raise RawOutputError("raw output exceeds the configured size limit")

        raw_root = self.data_dir / "raw"
        assessment_dir = raw_root / assessment_id
        run_dir = assessment_dir / tool_run_id
        for directory in (self.data_dir, raw_root, assessment_dir, run_dir):
            self._secure_directory(directory)

        output_path = run_dir / "raw-output.bin"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(output_path, flags, 0o600)
        except FileExistsError as exc:
            raise RawOutputError("raw output already exists and will not be overwritten") from exc
        except OSError as exc:
            raise RawOutputError("raw output could not be created safely") from exc

        try:
            with os.fdopen(descriptor, "wb") as output_file:
                output_file.write(content)
                output_file.flush()
                os.fsync(output_file.fileno())
            os.chmod(output_path, 0o400)
        except OSError as exc:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise RawOutputError("raw output write failed") from exc

        relative_path = output_path.relative_to(self.data_dir).as_posix()
        return StoredRawOutput(
            relative_path=relative_path,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
        )

    def read_verified(self, relative_path: str, expected_sha256: str) -> bytes:
        """Read a raw output only after path confinement and SHA-256 verification."""
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise RawOutputError("raw-output digest is invalid")
        content = self._read_confined(relative_path, "raw")
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise RawOutputError("raw output does not match its recorded SHA-256")
        return content

    def read_reference_file(self, relative_path: str) -> bytes:
        """Read a local reference file only from DATA_DIR/references, without following symlinks."""
        return self._read_confined(relative_path, "references")

    def _read_confined(self, relative_path: str, expected_root: str) -> bytes:
        """Read a bounded regular file under one approved DATA_DIR subdirectory."""
        if not relative_path or "\\" in relative_path or "\x00" in relative_path:
            raise RawOutputError("reference path is not a safe relative path")
        parts = Path(relative_path).parts
        if (
            Path(relative_path).is_absolute()
            or len(parts) < 2
            or parts[0] != expected_root
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise RawOutputError("reference path is outside the permitted data directory")

        root = self.data_dir / expected_root
        if root.is_symlink():
            raise RawOutputError("symlinks are not allowed in source directories")
        current = root
        for part in parts[1:]:
            current = current / part
            if current.is_symlink():
                raise RawOutputError("symlinks are not allowed in source files")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(current, flags)
        except OSError as exc:
            raise RawOutputError("source file could not be read safely") from exc
        try:
            with os.fdopen(descriptor, "rb") as source_file:
                if not stat.S_ISREG(os.fstat(source_file.fileno()).st_mode):
                    raise RawOutputError("source path is not a regular file")
                content = source_file.read(self.max_bytes + 1)
        except OSError as exc:
            raise RawOutputError("source file could not be read safely") from exc
        if len(content) > self.max_bytes:
            raise RawOutputError("source file exceeds the configured size limit")
        return content
