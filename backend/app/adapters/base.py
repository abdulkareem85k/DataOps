"""Base adapter framework for live security tools and scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.events import event_hub
from app.models.schemas import RawObservation, ToolRunCreate, ToolRunRead
from app.raw_output import RawOutputStore
from app.repo.assets import get_or_create_asset, get_or_create_service
from app.repo.audit import append_audit_event
from app.repo.tool_runs import (
    attach_tool_run_raw_output,
    create_tool_run,
    update_tool_run,
)
from app.scope.enforcement import ScopeToken, require_scope
from app.scope.models import ActionClass
from app.settings import Settings, get_settings


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(UTC)


class ToolAdapter(ABC):
    """Abstract base class for all scanner adapters."""

    name: str
    mode: Literal["live", "import"]
    capabilities: list[str]

    def __init__(
        self,
        settings: Settings | None = None,
        data_dir: Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.raw_store = RawOutputStore(data_dir or self.settings.data_dir)

    @abstractmethod
    async def check_availability(self) -> bool:
        """Check if scanner daemon or runner is reachable."""
        ...

    @abstractmethod
    def parse(self, raw_output: bytes, tool_run_id: str | None = None) -> list[RawObservation]:
        """Pure parse function mapping tool output bytes to RawObservation list."""
        ...

    @abstractmethod
    async def execute(
        self,
        target: str,
        args: dict[str, Any],
        token: ScopeToken,
    ) -> bytes:
        """Execute scanner against target using verified ScopeToken."""
        ...

    async def run(
        self,
        session: Session,
        assessment_id: str,
        target: str,
        action_class: ActionClass | str = "discovery",
        args: dict[str, Any] | None = None,
    ) -> tuple[ToolRunRead, list[RawObservation]]:
        """Check deterministic scope, invoke scanner, record immutable raw output,
        and parse observations.
        """
        arg_dict = args or {}
        cli_args: list[str] = []
        if "cli_args" in arg_dict and isinstance(arg_dict["cli_args"], (list, tuple)):
            cli_args = list(arg_dict["cli_args"])
        elif "args" in arg_dict and isinstance(arg_dict["args"], (list, tuple)):
            cli_args = list(arg_dict["args"])

        # 1. Scope gate: must verify scope first
        token = require_scope(
            session=session,
            assessment_id=assessment_id,
            tool=self.name,
            target=target,
            action_class=action_class,
            args=cli_args if cli_args else None,
            settings=self.settings,
        )

        recorded_args = [target] + [
            f"{k}={v}" for k, v in arg_dict.items() if k not in ("cli_args", "args")
        ]
        if cli_args:
            recorded_args.extend(cli_args)

        # 2. Record initial running ToolRun
        start_time = utc_now()
        tool_run = create_tool_run(
            session,
            ToolRunCreate(
                assessment_id=assessment_id,
                tool=self.name,
                mode=self.mode,
                args=recorded_args,
                status="running",
                started_at=start_time,
            ),
        )

        await event_hub.emit(
            assessment_id,
            "tool_run_status",
            {"tool_run_id": tool_run.id, "tool": self.name, "status": "running"},
        )

        append_audit_event(
            session,
            assessment_id=assessment_id,
            actor="agent",
            event_type=f"{self.name}.started",
            detail={"target": target, "tool_run_id": tool_run.id, "args": arg_dict},
            outcome="started",
        )

        # 3. Execute tool
        try:
            raw_bytes = await self.execute(target, arg_dict, token)
        except TimeoutError as exc:
            finish_time = utc_now()
            tool_run = update_tool_run(
                session,
                tool_run.id,
                status="timeout",
                error=f"Execution timed out: {exc}",
                finished_at=finish_time,
            )
            append_audit_event(
                session,
                assessment_id=assessment_id,
                actor="agent",
                event_type=f"{self.name}.timeout",
                detail={"target": target, "tool_run_id": tool_run.id, "error": str(exc)},
                outcome="timeout",
            )
            await event_hub.emit(
                assessment_id,
                "tool_run_status",
                {"tool_run_id": tool_run.id, "tool": self.name, "status": "timeout"},
            )
            return tool_run, []
        except Exception as exc:
            finish_time = utc_now()
            tool_run = update_tool_run(
                session,
                tool_run.id,
                status="failed",
                error=str(exc),
                finished_at=finish_time,
            )
            append_audit_event(
                session,
                assessment_id=assessment_id,
                actor="agent",
                event_type=f"{self.name}.failed",
                detail={"target": target, "tool_run_id": tool_run.id, "error": str(exc)},
                outcome="failed",
            )
            await event_hub.emit(
                assessment_id,
                "tool_run_status",
                {"tool_run_id": tool_run.id, "tool": self.name, "status": "failed"},
            )
            return tool_run, []

        # 4. Store raw output immutably
        stored = self.raw_store.store(assessment_id, tool_run.id, raw_bytes)
        tool_run = attach_tool_run_raw_output(session, tool_run.id, stored)

        # 5. Parse observations
        observations = self.parse(raw_bytes, tool_run_id=tool_run.id)

        # 6. Create Assets and Services
        for obs in observations:
            asset = get_or_create_asset(
                session,
                assessment_id,
                identifier=obs.asset_identifier,
                asset_type=obs.asset_type,
            )
            if obs.port is not None:
                get_or_create_service(
                    session,
                    asset_id=asset.id,
                    port=obs.port,
                    protocol=obs.protocol,
                    name=obs.service_name,
                    version=obs.service_version,
                )

        # 7. Succeeded lifecycle
        finish_time = utc_now()
        tool_run = update_tool_run(
            session,
            tool_run.id,
            status="succeeded",
            finished_at=finish_time,
        )
        append_audit_event(
            session,
            assessment_id=assessment_id,
            actor="agent",
            event_type=f"{self.name}.completed",
            detail={
                "target": target,
                "tool_run_id": tool_run.id,
                "observations_count": len(observations),
                "sha256": stored.sha256,
            },
            outcome="completed",
        )
        await event_hub.emit(
            assessment_id,
            "tool_run_status",
            {
                "tool_run_id": tool_run.id,
                "tool": self.name,
                "status": "succeeded",
                "observations_count": len(observations),
            },
        )
        return tool_run, observations
