"""Base file importer framework with XXE protection, size limits, and scope checking."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sqlalchemy.orm import Session

from app.models.schemas import RawObservation, ToolRunCreate, ToolRunRead
from app.raw_output import RawOutputStore
from app.repo.assets import get_or_create_asset, get_or_create_service
from app.repo.audit import append_audit_event
from app.repo.tool_runs import (
    attach_tool_run_raw_output,
    create_tool_run,
    update_tool_run,
)
from app.scope.engine import check_action
from app.settings import Settings, get_settings

MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(UTC)


class BaseImporter(ABC):
    """Abstract base class for all commercial report file importers."""

    name: str
    mode: Literal["import"] = "import"
    max_bytes: int = MAX_IMPORT_BYTES

    def __init__(
        self,
        settings: Settings | None = None,
        data_dir: Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.raw_store = RawOutputStore(
            data_dir or self.settings.data_dir, max_bytes=self.max_bytes
        )

    def check_host_in_scope(self, session: Session, assessment_id: str, host: str) -> bool:
        """Evaluate if an imported host target falls inside the registered assessment scope."""
        decision = check_action(
            session=session,
            assessment_id=assessment_id,
            tool=self.name,
            target=host,
            action_class="discovery",
            settings=self.settings,
        )
        return decision.allowed

    @abstractmethod
    def parse_content(
        self, content: bytes, tool_run_id: str | None = None
    ) -> dict[str, list[RawObservation]]:
        """Parse raw file bytes using defusedxml and return mapping of host -> observations."""
        ...

    def import_file(
        self,
        session: Session,
        assessment_id: str,
        filename: str,
        content: bytes,
    ) -> tuple[ToolRunRead, list[RawObservation], list[str]]:
        """Import a commercial report file with full auditability, scope filtering,
        and provenance.
        """
        if len(content) > self.max_bytes:
            raise ValueError(f"Import file exceeds maximum allowed size of {self.max_bytes} bytes")

        sha256 = hashlib.sha256(content).hexdigest()
        start_time = utc_now()

        # 1. Record initial ToolRun with mode="import"
        tool_run = create_tool_run(
            session,
            ToolRunCreate(
                assessment_id=assessment_id,
                tool=self.name,
                mode="import",
                args=[filename, f"sha256:{sha256}"],
                source_filename=filename,
                status="running",
                started_at=start_time,
            ),
        )

        # 2. Store immutable raw content
        stored = self.raw_store.store(assessment_id, tool_run.id, content)
        tool_run = attach_tool_run_raw_output(session, tool_run.id, stored)

        # 3. Parse XML using defusedxml
        observations_by_host = self.parse_content(content, tool_run_id=tool_run.id)

        # 4. Scope verification per host (skip and log out-of-scope targets)
        accepted_observations: list[RawObservation] = []
        skipped_hosts: list[str] = []

        for host, obs_list in observations_by_host.items():
            in_scope = self.check_host_in_scope(session, assessment_id, host)
            if not in_scope:
                skipped_hosts.append(host)
                append_audit_event(
                    session,
                    assessment_id=assessment_id,
                    actor="agent",
                    event_type=f"{self.name}.host_skipped_out_of_scope",
                    detail={
                        "host": host,
                        "source_filename": filename,
                        "tool_run_id": tool_run.id,
                        "skipped_observations_count": len(obs_list),
                    },
                    outcome="skipped",
                )
                continue

            # Target is in-scope: persist asset, services, and keep observations
            asset = get_or_create_asset(
                session,
                assessment_id=assessment_id,
                identifier=host,
                asset_type="host",
            )
            for obs in obs_list:
                if obs.port is not None:
                    get_or_create_service(
                        session,
                        asset_id=asset.id,
                        port=obs.port,
                        protocol=obs.protocol,
                        name=obs.service_name,
                        version=obs.service_version,
                    )
                accepted_observations.append(obs)

        # 5. Complete ToolRun lifecycle
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
            event_type=f"{self.name}.import_completed",
            detail={
                "source_filename": filename,
                "tool_run_id": tool_run.id,
                "observations_count": len(accepted_observations),
                "skipped_hosts_count": len(skipped_hosts),
                "sha256": sha256,
            },
            outcome="completed",
        )

        return tool_run, accepted_observations, skipped_hosts
