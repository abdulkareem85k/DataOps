from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.db import create_database_engine
from app.main import create_app
from app.settings import Settings


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "data_dir": tmp_path,
        "db_url": f"sqlite:///{tmp_path / 'vapt.db'}",
    }
    values.update(overrides)
    return Settings(
        _env_file=None,
        **values,
    )


def test_health_returns_ok_and_database_uses_wal(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    engine = create_database_engine(settings)
    client = TestClient(create_app(settings, engine))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.text == "OK"
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
    engine.dispose()


def test_health_does_not_expose_api_documentation(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path))
    client = TestClient(app)

    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_non_sqlite_database_url_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        make_settings(tmp_path, db_url="mysql://example.invalid/vapt")


def test_non_private_lab_cidr_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        make_settings(tmp_path, lab_cidr="8.8.8.0/24")
