"""FastAPI application factory for the VAPT backend foundation."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from app.db import configure_session_factory, create_database_engine, initialize_database
from app.logging_config import configure_logging
from app.settings import Settings, get_settings

configure_logging()
logger = logging.getLogger("vapt_agent.backend")


def create_app(
    settings: Settings | None = None,
    engine: Engine | None = None,
) -> FastAPI:
    """Create the API app; dependency injection keeps database tests isolated."""
    effective_settings = settings or get_settings()
    app: FastAPI

    def get_engine() -> Engine:
        if app.state.engine is None:
            app.state.engine = create_database_engine(effective_settings)
        if not app.state.database_initialized:
            initialize_database(app.state.engine)
            configure_session_factory(app.state.engine)
            app.state.database_initialized = True
        return app.state.engine

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Create the declared local schema before the backend reports readiness."""
        logger.info("backend_starting")
        get_engine()
        logger.info("backend_started")
        try:
            yield
        finally:
            logger.info("backend_stopped")
            if app.state.owns_engine and app.state.engine is not None:
                app.state.engine.dispose()

    app = FastAPI(
        title="AI Unified VAPT Agent API",
        version="0.2.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = effective_settings
    app.state.engine = engine
    app.state.owns_engine = engine is None
    app.state.database_initialized = False

    @app.get("/health", response_class=PlainTextResponse, include_in_schema=False)
    def health() -> str:
        """Return plain-text OK only after schema setup and a SQLite query succeed."""
        try:
            with get_engine().connect() as connection:
                connection.execute(text("SELECT 1"))
        except (SQLAlchemyError, OSError, ValueError) as exc:
            logger.error("health_check_failed")
            raise HTTPException(status_code=503, detail="not ready") from exc
        return "OK"

    @app.get("/", response_class=PlainTextResponse, include_in_schema=False)
    def root() -> str:
        return "AI Unified VAPT Agent API"

    from app.api.imports import router as imports_router
    from app.api.scope import router as scope_router
    from app.api.tool_runs import router as tool_runs_router

    app.include_router(scope_router)
    app.include_router(tool_runs_router)
    app.include_router(imports_router)

    return app


app = create_app()
