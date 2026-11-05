from __future__ import annotations

from pathlib import Path

import pytest

from app.audit import AuditChainError, HashChainedAuditLog


def test_appends_hash_chained_events(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = HashChainedAuditLog(path)

    first = log.append(
        action="scan.started",
        tool="nmap",
        target_ref="172.30.0.10",
        status="started",
    )
    second = log.append(
        action="scan.completed",
        tool="nmap",
        target_ref="172.30.0.10",
        status="completed",
        exit_code=0,
    )

    assert first["previous_hash"] == "0" * 64
    assert second["previous_hash"] == first["hash"]
    assert path.read_text(encoding="utf-8").count("\n") == 2


def test_tampering_prevents_future_appends(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = HashChainedAuditLog(path)
    log.append(action="scan.started", tool="nmap", target_ref="x", status="started")
    path.write_text('{"tampered":true}\n', encoding="utf-8")

    with pytest.raises(AuditChainError):
        log.append(action="scan.completed", tool="nmap", target_ref="x", status="completed")
