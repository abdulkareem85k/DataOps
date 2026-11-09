"""Assessment repository functions."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.orm import Assessment
from app.models.schemas import AssessmentCreate, AssessmentRead
from app.repo.common import RecordNotFound, as_utc, new_id


def create_assessment(session: Session, payload: AssessmentCreate) -> AssessmentRead:
    """Persist and return an assessment without creating synthetic child records."""
    row = Assessment(id=new_id("ASM"), name=payload.name, description=payload.description)
    session.add(row)
    session.flush()
    return to_assessment_read(row)


def get_assessment(session: Session, assessment_id: str) -> AssessmentRead:
    """Read one assessment or raise RecordNotFound."""
    row = session.get(Assessment, assessment_id)
    if row is None:
        raise RecordNotFound("assessment not found")
    return to_assessment_read(row)


def list_assessments(session: Session) -> list[AssessmentRead]:
    """Return all assessments ordered by created_at desc."""
    rows = (
        session.execute(select(Assessment).order_by(Assessment.created_at.desc())).scalars().all()
    )
    return [to_assessment_read(row) for row in rows]


def to_assessment_read(row: Assessment) -> AssessmentRead:
    """Map an Assessment ORM row to the public read schema."""
    return AssessmentRead(
        id=row.id,
        name=row.name,
        description=row.description,
        created_at=as_utc(row.created_at),
    )


class AssessmentRepository:
    """Session-factory wrapper used by existing services."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def create(self, payload: AssessmentCreate) -> AssessmentRead:
        """Persist and return an assessment without creating synthetic child records."""
        with self.sessions.begin() as session:
            return create_assessment(session, payload)

    def get(self, assessment_id: str) -> AssessmentRead:
        """Read one assessment or raise RecordNotFound."""
        with self.sessions() as session:
            return get_assessment(session, assessment_id)
