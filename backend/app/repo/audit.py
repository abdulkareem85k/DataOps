"""Append-only hash-chained audit log. No update or delete functions exist."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.orm import Assessment, AuditEvent
from app.models.schemas import AuditEventRead
from app.repo.common import AuditChainError, RecordNotFound, as_utc, new_id

GENESIS_HASH = "0" * 64
AuditActor = Literal["user", "agent", "scope-engine", "system"]


def _canonical_json(value: Any) -> str:
    """Serialize event fields with sorted keys for a stable hash input."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(*, prev_hash: str, canonical_body: str) -> str:
    """Return sha256(prev_hash + canonical JSON of the event)."""
    return hashlib.sha256(f"{prev_hash}{canonical_body}".encode()).hexdigest()


def _event_body(row: AuditEvent) -> dict[str, Any]:
    """Fields included in the chained hash; the hash itself is excluded."""
    return {
        "id": row.id,
        "assessment_id": row.assessment_id,
        "seq": row.seq,
        "timestamp": as_utc(row.timestamp).replace(microsecond=0).isoformat(),
        "actor": row.actor,
        "event_type": row.event_type,
        "detail": row.detail,
        "outcome": row.outcome,
        "prev_hash": row.prev_hash,
    }


def append_audit_event(
    session: Session,
    *,
    assessment_id: str,
    actor: AuditActor,
    event_type: str,
    detail: dict[str, Any],
    outcome: str,
) -> AuditEventRead:
    """Append one audit event and compute its hash-chain linkage."""
    if session.get(Assessment, assessment_id) is None:
        raise RecordNotFound("assessment not found")

    last = session.execute(
        select(AuditEvent)
        .where(AuditEvent.assessment_id == assessment_id)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
        .with_for_update()
    ).scalar_one_or_none()

    seq = 1 if last is None else last.seq + 1
    prev_hash = GENESIS_HASH if last is None else last.event_hash
    row = AuditEvent(
        id=new_id("AUD"),
        assessment_id=assessment_id,
        seq=seq,
        timestamp=datetime.now(UTC).replace(microsecond=0),
        actor=actor,
        event_type=event_type,
        detail=detail,
        outcome=outcome,
        prev_hash=prev_hash,
        event_hash="pending",
    )
    session.add(row)
    session.flush()
    body = _canonical_json(_event_body(row))
    row.event_hash = compute_event_hash(prev_hash=prev_hash, canonical_body=body)
    session.flush()
    return to_audit_read(row)


def verify_chain(session: Session, assessment_id: str) -> bool:
    """Recompute hashes in sequence order; return False if any link is broken."""
    if session.get(Assessment, assessment_id) is None:
        raise RecordNotFound("assessment not found")
    rows = (
        session.execute(
            select(AuditEvent)
            .where(AuditEvent.assessment_id == assessment_id)
            .order_by(AuditEvent.seq.asc())
        )
        .scalars()
        .all()
    )
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for row in rows:
        if row.seq != expected_seq:
            return False
        if row.prev_hash != expected_prev:
            return False
        body = _canonical_json(_event_body(row))
        expected_hash = compute_event_hash(prev_hash=row.prev_hash, canonical_body=body)
        if row.event_hash != expected_hash:
            return False
        expected_prev = row.event_hash
        expected_seq += 1
    return True


def list_audit_events(session: Session, assessment_id: str) -> list[AuditEventRead]:
    """Return the assessment audit chain in sequence order."""
    rows = (
        session.execute(
            select(AuditEvent)
            .where(AuditEvent.assessment_id == assessment_id)
            .order_by(AuditEvent.seq.asc())
        )
        .scalars()
        .all()
    )
    return [to_audit_read(row) for row in rows]


def to_audit_read(row: AuditEvent) -> AuditEventRead:
    """Map an AuditEvent ORM row to the public read schema."""
    return AuditEventRead(
        id=row.id,
        assessment_id=row.assessment_id,
        seq=row.seq,
        timestamp=as_utc(row.timestamp),
        actor=row.actor,  # type: ignore[arg-type]
        event_type=row.event_type,
        detail=dict(row.detail or {}),
        outcome=row.outcome,
        prev_hash=row.prev_hash,
        hash=row.event_hash,
        created_at=as_utc(row.created_at),
    )


class AuditRepository:
    """Session-factory wrapper. Intentionally exposes only append and verify."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def append_audit_event(
        self,
        *,
        assessment_id: str,
        actor: AuditActor,
        event_type: str,
        detail: dict[str, Any],
        outcome: str,
    ) -> AuditEventRead:
        """Append one chained audit event in its own transaction."""
        if not event_type:
            raise AuditChainError("event_type is required")
        with self.sessions.begin() as session:
            return append_audit_event(
                session,
                assessment_id=assessment_id,
                actor=actor,
                event_type=event_type,
                detail=detail,
                outcome=outcome,
            )

    def verify_chain(self, assessment_id: str) -> bool:
        """Verify the hash chain for one assessment."""
        with self.sessions() as session:
            return verify_chain(session, assessment_id)
