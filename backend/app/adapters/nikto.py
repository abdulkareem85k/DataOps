"""Nikto scanner adapter calling scanner-runner REST API."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from app.adapters.base import ToolAdapter, utc_now
from app.models.schemas import RawObservation
from app.scope.enforcement import ScopeToken

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NiktoAdapter(ToolAdapter):
    """Live Nikto web server scanner adapter communicating via scanner-runner API."""

    name = "nikto"
    mode = "live"
    capabilities = ["web_server_misconfig", "outdated_components", "dangerous_files"]

    async def check_availability(self) -> bool:
        """Probe runner health endpoint."""
        url = f"{self.settings.runner_url.rstrip('/')}/health"
        headers = {}
        token = self.settings.runner_token.get_secret_value()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=headers)
                return resp.status_code == 200
        except Exception:
            return False

    async def execute(
        self,
        target: str,
        args: dict[str, Any],
        token: ScopeToken,
    ) -> bytes:
        """Call runner POST /run/nikto and return raw stdout JSON bytes."""
        url = f"{self.settings.runner_url.rstrip('/')}/run/nikto"
        headers = {
            "Content-Type": "application/json",
        }
        secret_token = self.settings.runner_token.get_secret_value()
        if secret_token:
            headers["Authorization"] = f"Bearer {secret_token}"

        # Clean host/port from target if URL passed
        host = target
        port = int(args.get("port", 80))
        use_https = bool(args.get("use_https", False))

        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
            if parsed.port:
                port = parsed.port
            if parsed.scheme == "https":
                use_https = True

        approval_id = str(args.get("approval_id") or f"appr-{token.assessment_id[:16]}")
        if len(approval_id) < 8:
            approval_id = f"{approval_id}-approved"

        payload = {
            "target": host,
            "port": port,
            "use_https": use_https,
            "timeout_seconds": int(args.get("timeout_seconds", 90)),
            "approval_id": approval_id,
        }

        timeout = payload["timeout_seconds"] + 15
        async with httpx.AsyncClient(timeout=float(timeout)) as client:
            try:
                resp = await client.post(url, json=payload, headers=headers)
            except httpx.TimeoutException as exc:
                raise TimeoutError(f"Nikto runner connection timed out: {exc}") from exc

            if resp.status_code == 504:
                raise TimeoutError("Nikto execution timed out in runner")
            if resp.status_code != 200:
                raise RuntimeError(f"Runner returned HTTP {resp.status_code}: {resp.text}")

            data = resp.json()
            if data.get("status") == "failed" and data.get("exit_code") != 0:
                raise RuntimeError(
                    f"Nikto exited with code {data.get('exit_code')}: {data.get('stderr')}"
                )

            stdout = data.get("stdout", "")
            return stdout.encode("utf-8")

    def parse(self, raw_output: bytes, tool_run_id: str | None = None) -> list[RawObservation]:
        """Parse Nikto JSON output into RawObservation list."""
        if not raw_output or not raw_output.strip():
            return []

        try:
            data = json.loads(raw_output.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise ValueError(f"Failed to parse Nikto JSON: {exc}") from exc

        run_id = tool_run_id or ""
        now = utc_now()
        observations: list[RawObservation] = []

        host = data.get("host") or data.get("ip") or "unknown"
        port = int(data.get("port", 80))
        banner = data.get("banner", "")
        vulns = data.get("vulnerabilities", [])

        # If banner is present, record a service version observation
        if banner:
            obs = RawObservation(
                tool=self.name,
                asset_identifier=host,
                asset_type="web_application",
                port=port,
                protocol="tcp",
                service_name="http",
                service_version=banner,
                title=f"Nikto Web Server Banner: {banner}",
                description=f"Web server on port {port} banner: {banner}",
                severity="info",
                confidence="high",
                confidence_score=0.9,
                category="exposure",
                raw_ref={"tool_run_id": run_id, "json_pointer": "/banner"},
                evidence=banner,
                timestamp=now,
            )
            observations.append(obs)

        for idx, item in enumerate(vulns):
            item_id = item.get("id", str(idx))
            osvdb = str(item.get("OSVDB", "0"))
            url_path = item.get("url", "")
            msg = item.get("msg", "")
            cves = sorted(set(CVE_PATTERN.findall(msg)))

            # Deduce severity and category
            severity = "low"
            if cves or (osvdb and osvdb != "0"):
                severity = "medium"

            category = "misconfig"
            if cves:
                category = "outdated_software"
            elif any(k in msg.lower() for k in ("index", "directory", "default file")):
                category = "exposure"

            references: list[str] = []
            if osvdb and osvdb != "0":
                references.append(f"https://vulners.com/osvdb/OSVDB:{osvdb}")

            obs = RawObservation(
                tool=self.name,
                asset_identifier=host,
                asset_type="web_application",
                port=port,
                protocol="tcp",
                service_name="http",
                title=f"Nikto: {msg[:80]}",
                description=msg,
                severity=severity,
                confidence="medium",
                confidence_score=0.7,
                category=category,
                url=url_path if url_path else None,
                cve_ids=cves,
                raw_ref={"tool_run_id": run_id, "json_pointer": f"/vulnerabilities/{idx}"},
                evidence=f"ID: {item_id}, OSVDB: {osvdb}, URL: {url_path}, Msg: {msg}",
                references=references,
                timestamp=now,
            )
            observations.append(obs)

        return observations
