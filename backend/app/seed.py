"""Initialize the local SQLite file without creating synthetic assessments/findings."""

from __future__ import annotations

from app.db import create_database_engine, initialize_database
from app.settings import get_settings


def main() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    initialize_database(engine)
    with engine.connect() as connection:
        mode = connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()
    if str(mode).lower() != "wal":
        raise RuntimeError("SQLite WAL mode was not enabled")
    print("SQLite schema initialized in WAL mode; no sample findings or targets were created.")
    engine.dispose()


if __name__ == "__main__":
    main()
