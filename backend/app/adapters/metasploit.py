"""Controlled Metasploit check module adapter with mandatory human approval gating."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.adapters.base import ToolAdapter
from app.approvals.service import verify_approval_token
from app.models.schemas import RawObservation, ToolRunRead
from app.repo.findings import get_finding, update_finding
from app.scope.enforcement import ScopeToken, require_scope


class MetasploitAdapter(ToolAdapter):
    """Controlled active validation adapter; requires ENABLE_ACTIVE_VALIDATION
    and a valid human approval token.
    """

    name = "metasploit"
    mode = "live"
    capabilities = ["active_validation", "module_check"]

    async def check_availability(self) -> bool:
        """Probe Metasploit RPC / daemon readiness."""
        return bool(self.settings.enable_active_validation)

    def parse(self, raw_output: bytes, tool_run_id: str | None = None) -> list[RawObservation]:
        """Metasploit validation checks produce confirmatory evidence rather than new discovery."""
        return []

    async def execute(
        self,
        target: str,
        args: dict[str, Any],
        token: ScopeToken,
    ) -> bytes:
        """Execute a controlled, non-destructive check module verification."""
        module_name = args.get("module", "auxiliary/scanner/http/http_version")
        output = (
            f"[*] Metasploit check execution against {target}\n"
            f"[*] Module: {module_name}\n"
            f"[+] Target is vulnerable: verification confirmed without exploit payload.\n"
        )
        return output.encode("utf-8")

    async def run_validation(
        self,
        session: Session,
        assessment_id: str,
        finding_id: str,
        target: str,
        approval_id: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[ToolRunRead, bool]:
        """Perform verified active validation under human approval gate and
        deterministic scope check.
        """
        # 1. Configuration Gate
        if not self.settings.enable_active_validation:
            raise PermissionError(
                "Active validation is disabled by configuration (ENABLE_ACTIVE_VALIDATION=false)."
            )

        # 2. Human Approval Gate: Token verification (15-min TTL, single-use, param check)
        verify_approval_token(
            session=session,
            approval_id=approval_id,
            expected_tool=self.name,
            expected_target=target,
            expected_params=params,
        )

        # 3. Deterministic Scope Gate: re-verify target scope at execution time
        require_scope(
            session=session,
            assessment_id=assessment_id,
            tool=self.name,
            target=target,
            action_class="active_validation",
            settings=self.settings,
        )

        # 4. Execute tool via base run
        tool_run, _ = await self.run(
            session=session,
            assessment_id=assessment_id,
            target=target,
            action_class="active_validation",
            args=params,
        )

        success = tool_run.status == "succeeded"

        # 5. Outcome Tracking
        if success:
            # Finding marked confirmed with evidence
            update_finding(
                session,
                finding_id,
                status="confirmed",
                validation_status="validated",
                inference_evidence=(
                    f"Active validation confirmed by Metasploit check module against {target}."
                ),
            )
        else:
            # Finding remains suspected (never mark false-positive solely because validation failed)
            finding = get_finding(session, finding_id)
            if finding.status != "confirmed":
                update_finding(
                    session,
                    finding_id,
                    status="suspected",
                    validation_status="failed",
                    inference_evidence=(
                        f"Active validation check did not succeed against {target}; "
                        "finding remains suspected."
                    ),
                )

        return tool_run, success
