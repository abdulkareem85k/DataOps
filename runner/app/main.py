"""Restricted internal scanner API with per-request target validation."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import subprocess
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

from app.audit import AuditChainError, HashChainedAuditLog
from app.execution import (
    CommandSpec,
    build_nmap_command,
    execute_command,
)
from app.schemas import NiktoRequest, NmapRequest, ScanResponse
from app.scope import ScopeViolation, validate_lab_target
from app.settings import RunnerSettings

logger = logging.getLogger("vapt_agent.runner")


def _target_reference(raw_target: str) -> str:
    """Avoid persisting malformed, arbitrary input while correlating a rejection."""
    return "sha256:" + hashlib.sha256(raw_target.encode("utf-8", errors="replace")).hexdigest()[:16]


def create_app(
    settings: RunnerSettings | None = None,
    audit_log: HashChainedAuditLog | None = None,
) -> FastAPI:
    """Create a runner app with injectable settings and audit storage for tests."""
    effective_settings = settings or RunnerSettings()
    audit = audit_log or HashChainedAuditLog(effective_settings.audit_path)
    app = FastAPI(
        title="Restricted VAPT Scanner Runner",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = effective_settings
    app.state.audit_log = audit

    def append_event(
        *,
        action: str,
        tool: str,
        target_ref: str,
        status: str,
        approval_id: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        try:
            audit.append(
                action=action,
                tool=tool,
                target_ref=target_ref,
                status=status,
                approval_id=approval_id,
                exit_code=exit_code,
            )
        except AuditChainError as exc:
            logger.error("runner_audit_unavailable")
            raise HTTPException(status_code=503, detail="audit log unavailable") from exc

    def require_bearer(authorization: str | None = Header(default=None)) -> None:
        expected = effective_settings.runner_token.get_secret_value()
        if not expected:
            raise HTTPException(status_code=503, detail="runner token is not configured")
        scheme, separator, provided = (authorization or "").partition(" ")
        if not separator or scheme.lower() != "bearer" or not secrets.compare_digest(
            provided, expected
        ):
            append_event(
                action="runner.auth_rejected",
                tool="runner",
                target_ref="unavailable",
                status="rejected",
            )
            raise HTTPException(
                status_code=401,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def require_backend_source(request: Request) -> None:
        """Accept scan calls only from the statically addressed backend service."""
        client_host = request.client.host if request.client is not None else ""
        if client_host != str(effective_settings.runner_backend_ip):
            append_event(
                action="runner.source_rejected",
                tool="runner",
                target_ref="unavailable",
                status="source_not_backend",
            )
            raise HTTPException(status_code=403, detail="scanner API is backend-only")

    @app.get("/health", response_class=PlainTextResponse, include_in_schema=False)
    def health(request: Request) -> str:
        """Expose readiness only to the backend and the container's own healthcheck."""
        client_host = request.client.host if request.client is not None else ""
        trusted_hosts = {str(effective_settings.runner_backend_ip), "127.0.0.1", "::1"}
        if client_host not in trusted_hosts:
            append_event(
                action="runner.source_rejected",
                tool="runner",
                target_ref="unavailable",
                status="source_not_backend",
            )
            raise HTTPException(status_code=403, detail="runner is backend-only")
        return "OK"

    async def run_scan(
        tool: Literal["nmap", "nikto"],
        target_input: str,
        command: CommandSpec,
        approval_id: str | None = None,
    ) -> ScanResponse:
        # Recheck scope at the runner boundary immediately before starting the process.
        try:
            target = validate_lab_target(target_input, effective_settings.lab_cidr)
        except ScopeViolation as exc:
            append_event(
                action="scope.rejected",
                tool=tool,
                target_ref=_target_reference(target_input),
                status=exc.reason_code,
                approval_id=approval_id,
            )
            raise HTTPException(status_code=403, detail="target rejected by lab scope") from exc

        append_event(
            action="scan.started",
            tool=tool,
            target_ref=str(target),
            status="started",
            approval_id=approval_id,
        )
        try:
            exit_code, stdout, stderr, truncated = await asyncio.to_thread(
                execute_command, command
            )
        except subprocess.TimeoutExpired as exc:
            append_event(
                action="scan.failed",
                tool=tool,
                target_ref=str(target),
                status="timeout",
                approval_id=approval_id,
            )
            raise HTTPException(status_code=504, detail="scanner timed out") from exc
        except OSError as exc:
            append_event(
                action="scan.failed",
                tool=tool,
                target_ref=str(target),
                status="execution_error",
                approval_id=approval_id,
            )
            raise HTTPException(status_code=503, detail="scanner execution failed") from exc

        append_event(
            action="scan.completed" if exit_code == 0 else "scan.failed",
            tool=tool,
            target_ref=str(target),
            status="completed" if exit_code == 0 else "nonzero_exit",
            approval_id=approval_id,
            exit_code=exit_code,
        )
        return ScanResponse(
            tool=tool,
            target=str(target),
            status="completed" if exit_code == 0 else "failed",
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
        )

    @app.post(
        "/run/nmap",
        response_model=ScanResponse,
        dependencies=[Depends(require_backend_source), Depends(require_bearer)],
    )
    async def run_nmap(request: NmapRequest) -> ScanResponse:
        command = build_nmap_command(request, request.target)
        return await run_scan("nmap", request.target, command)

    @app.post(
        "/run/nikto",
        response_model=ScanResponse,
        dependencies=[Depends(require_backend_source), Depends(require_bearer)],
    )
    async def run_nikto(request: NiktoRequest) -> ScanResponse:
        if not effective_settings.enable_active_validation:
            append_event(
                action="scan.rejected",
                tool="nikto",
                target_ref=_target_reference(request.target),
                status="active_validation_disabled",
                approval_id=request.approval_id,
            )
            raise HTTPException(status_code=403, detail="active validation is disabled")
        append_event(
            action="scan.rejected",
            tool="nikto",
            target_ref=_target_reference(request.target),
            status="recorded_approval_workflow_unavailable",
            approval_id=request.approval_id,
        )
        raise HTTPException(
            status_code=409,
            detail=(
                "active validation remains unavailable until recorded human approvals "
                "are implemented"
            ),
        )

    return app


app = create_app()
