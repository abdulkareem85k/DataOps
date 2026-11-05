"""Append-only JSONL audit chain for runner requests, decisions, and outcomes."""

from __future__ import annotations

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


class AuditChainError(RuntimeError):
    """Raised when the append-only audit chain cannot be trusted or extended."""


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _verify_and_get_head(handle: Any) -> str:
    handle.seek(0)
    previous_hash = GENESIS_HASH
    for line_number, line in enumerate(handle, start=1):
        try:
            record = json.loads(line)
            stored_hash = record.pop("hash")
            stored_previous = record.pop("previous_hash")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AuditChainError(f"invalid audit record at line {line_number}") from exc
        if stored_previous != previous_hash:
            raise AuditChainError(f"broken audit link at line {line_number}")
        expected_hash = hashlib.sha256(
            (previous_hash + _canonical_json(record)).encode("utf-8")
        ).hexdigest()
        if stored_hash != expected_hash:
            raise AuditChainError(f"audit hash mismatch at line {line_number}")
        previous_hash = stored_hash
    return previous_hash


class HashChainedAuditLog:
    """Append records under a file lock and fail closed on any chain corruption."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(
        self,
        *,
        action: str,
        tool: str,
        target_ref: str,
        status: str,
        approval_id: str | None = None,
        exit_code: int | None = None,
    ) -> dict[str, Any]:
        """Append a hash-linked record and fsync it before returning."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("a+", encoding="utf-8") as handle:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    previous_hash = _verify_and_get_head(handle)
                    payload: dict[str, Any] = {
                        "timestamp": datetime.now(UTC).isoformat(),
                        "action": action,
                        "tool": tool,
                        "target_ref": target_ref,
                        "status": status,
                        "approval_id": approval_id,
                        "exit_code": exit_code,
                    }
                    entry_hash = hashlib.sha256(
                        (previous_hash + _canonical_json(payload)).encode("utf-8")
                    ).hexdigest()
                    record = payload | {"previous_hash": previous_hash, "hash": entry_hash}
                    handle.seek(0, os.SEEK_END)
                    handle.write(_canonical_json(record) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                    return record
                finally:
                    if fcntl is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise AuditChainError("unable to append runner audit record") from exc
