"""Asset and Service repository functions."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.orm import Assessment, Asset, Service
from app.models.schemas import AssetCreate, AssetRead, ServiceCreate, ServiceRead
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


def list_assets(session: Session, assessment_id: str) -> list[AssetRead]:
    """List all assets for an assessment."""
    rows = (
        session.execute(
            select(Asset)
            .where(Asset.assessment_id == assessment_id)
            .order_by(Asset.created_at.asc())
        )
        .scalars()
        .all()
    )
    return [to_asset_read(row) for row in rows]


def get_or_create_asset(
    session: Session,
    assessment_id: str,
    identifier: str,
    asset_type: str = "host",
    attributes: dict[str, Any] | None = None,
) -> AssetRead:
    """Find existing asset by (assessment_id, identifier) or create one."""
    row = (
        session.execute(
            select(Asset).where(
                Asset.assessment_id == assessment_id,
                Asset.identifier == identifier,
            )
        )
        .scalars()
        .first()
    )
    if row is not None:
        if attributes:
            merged = dict(row.attributes)
            merged.update(attributes)
            row.attributes = merged
            session.flush()
        return to_asset_read(row)

    payload = AssetCreate(
        assessment_id=assessment_id,
        identifier=identifier,
        asset_type=asset_type,
        attributes=attributes or {},
    )
    return create_asset(session, payload)


def create_service(session: Session, payload: ServiceCreate) -> ServiceRead:
    """Persist one service under an existing asset."""
    if session.get(Asset, payload.asset_id) is None:
        raise RecordNotFound("asset not found")
    row = Service(
        id=new_id("SVC"),
        asset_id=payload.asset_id,
        port=payload.port,
        protocol=payload.protocol,
        name=payload.name,
        version=payload.version,
        attributes=payload.attributes,
    )
    session.add(row)
    session.flush()
    return to_service_read(row)


def get_service(session: Session, service_id: str) -> ServiceRead:
    """Read one service or raise RecordNotFound."""
    row = session.get(Service, service_id)
    if row is None:
        raise RecordNotFound("service not found")
    return to_service_read(row)


def list_services(session: Session, asset_id: str) -> list[ServiceRead]:
    """List all services for an asset."""
    rows = (
        session.execute(
            select(Service)
            .where(Service.asset_id == asset_id)
            .order_by(Service.port.asc().nulls_last())
        )
        .scalars()
        .all()
    )
    return [to_service_read(row) for row in rows]


def get_or_create_service(
    session: Session,
    asset_id: str,
    port: int | None,
    protocol: str | None,
    name: str | None = None,
    version: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> ServiceRead:
    """Find existing service on asset by (port, protocol) or create one."""
    query = select(Service).where(Service.asset_id == asset_id)
    if port is not None:
        query = query.where(Service.port == port)
    else:
        query = query.where(Service.port.is_(None))

    if protocol is not None:
        query = query.where(Service.protocol == protocol)
    else:
        query = query.where(Service.protocol.is_(None))

    row = session.execute(query).scalars().first()
    if row is not None:
        updated = False
        if name and not row.name:
            row.name = name
            updated = True
        if version and not row.version:
            row.version = version
            updated = True
        if attributes:
            merged = dict(row.attributes)
            merged.update(attributes)
            row.attributes = merged
            updated = True
        if updated:
            session.flush()
        return to_service_read(row)

    payload = ServiceCreate(
        asset_id=asset_id,
        port=port,
        protocol=protocol,
        name=name,
        version=version,
        attributes=attributes or {},
    )
    return create_service(session, payload)


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


def to_service_read(row: Service) -> ServiceRead:
    """Map a Service ORM row to the public read schema."""
    return ServiceRead(
        id=row.id,
        asset_id=row.asset_id,
        port=row.port,
        protocol=row.protocol,
        name=row.name,
        version=row.version,
        attributes=dict(row.attributes),
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

    def list(self, assessment_id: str) -> list[AssetRead]:
        with self.sessions() as session:
            return list_assets(session, assessment_id)

    def get_or_create(
        self,
        assessment_id: str,
        identifier: str,
        asset_type: str = "host",
        attributes: dict[str, Any] | None = None,
    ) -> AssetRead:
        with self.sessions.begin() as session:
            return get_or_create_asset(session, assessment_id, identifier, asset_type, attributes)

    def create_service(self, payload: ServiceCreate) -> ServiceRead:
        with self.sessions.begin() as session:
            return create_service(session, payload)

    def get_service(self, service_id: str) -> ServiceRead:
        with self.sessions() as session:
            return get_service(session, service_id)

    def list_services(self, asset_id: str) -> list[ServiceRead]:
        with self.sessions() as session:
            return list_services(session, asset_id)

    def get_or_create_service(
        self,
        asset_id: str,
        port: int | None,
        protocol: str | None,
        name: str | None = None,
        version: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> ServiceRead:
        with self.sessions.begin() as session:
            return get_or_create_service(
                session, asset_id, port, protocol, name, version, attributes
            )
