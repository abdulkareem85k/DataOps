"""SQLAlchemy 2.0 engine/session helpers with SQLite WAL mode."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.settings import Settings

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def create_database_engine(settings: Settings) -> Engine:
    """Create the configured SQLite engine and enforce WAL-related pragmas."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    url = make_url(settings.db_url)
    database_name = url.database
    if not database_name or database_name == ":memory:":
        raise ValueError("DB_URL must point to a persistent SQLite file")

    database_path = Path(database_name).expanduser()
    database_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        url,
        connect_args={"check_same_thread": False, "timeout": 5},
        pool_pre_ping=True,
    )

    @event.listens_for(engine, "connect")
    def configure_sqlite(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine


def initialize_database(engine: Engine) -> None:
    """Create all declared tables and initialize the sequential finding counter."""
    from app.models.orm import Base

    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO id_counters (name, value) VALUES (?, ?)",
            ("finding", 0),
        )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return short-lived sessions suitable for repository transactions."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def configure_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Bind the process-wide session factory used by FastAPI's get_session dependency."""
    global _engine, _SessionLocal
    _engine = engine
    _SessionLocal = create_session_factory(engine)
    return _SessionLocal


def get_session() -> Iterator[Session]:
    """Yield a request-scoped SQLAlchemy session and commit on success."""
    if _SessionLocal is None:
        raise RuntimeError("database is not configured")
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
