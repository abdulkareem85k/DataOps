"""Asset repository functions."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.models.orm import Assessment, Asset
from app.models.schemas import AssetCreate, AssetRead
from app.repo.common import RecordNotFound, as_utc, new_id


def create_asset(session: Session, payload: AssetCreate) -> AssetRead:
    """Persist one asset under an existing assessment."""
    if session.get(Assessment, payload.assessment_id) is None:
        raise RecordNotFound("assessment not found")
    row = Asset(
        id=new_id("AST"),
        assessment_id=payload.assessment_id,
        identifier=payload.identifier,
        asset_type=payload.asset_type,
        attributes=payload.attributes,
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
    )
    session.add(row)
    session.flush()
    return to_asset_read(row)


def get_asset(session: Session, asset_id: str) -> AssetRead:
    """Read one asset or raise RecordNotFound."""
    row = session.get(Asset, asset_id)
    if row is None:
        raise RecordNotFound("asset not found")
    return to_asset_read(row)


def to_asset_read(row: Asset) -> AssetRead:
    """Map an Asset ORM row to the public read schema."""
    return AssetRead(
        id=row.id,
        assessment_id=row.assessment_id,
        identifier=row.identifier,
        asset_type=row.asset_type,
        attributes=dict(row.attributes),
        first_seen=as_utc(row.first_seen) if row.first_seen else None,
        last_seen=as_utc(row.last_seen) if row.last_seen else None,
        created_at=as_utc(row.created_at),
    )


class AssetRepository:
    """Session-factory wrapper used by existing services."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def create(self, payload: AssetCreate) -> AssetRead:
        with self.sessions.begin() as session:
            return create_asset(session, payload)

    def get(self, asset_id: str) -> AssetRead:
        with self.sessions() as session:
            return get_asset(session, asset_id)
