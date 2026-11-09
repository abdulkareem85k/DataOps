"""Nmap scanner adapter using scanner-runner REST API and defusedxml."""

from __future__ import annotations

import re
from typing import Any

import defusedxml.ElementTree as ET
import httpx

from app.adapters.base import ToolAdapter, utc_now
from app.models.schemas import RawObservation
from app.scope.enforcement import ScopeToken

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NmapAdapter(ToolAdapter):
    """Live Nmap scanner adapter invoking the isolated scanner-runner container."""

    name = "nmap"
    mode = "live"
    capabilities = ["host_discovery", "port_scan", "service_scan", "targeted_scripts"]

    async def check_availability(self) -> bool:
        """Probe scanner runner health endpoint."""
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
        """Call runner POST /run/nmap and return raw stdout XML bytes."""
        url = f"{self.settings.runner_url.rstrip('/')}/run/nmap"
        headers = {
            "Content-Type": "application/json",
        }
        secret_token = self.settings.runner_token.get_secret_value()
        if secret_token:
            headers["Authorization"] = f"Bearer {secret_token}"

        payload = {
            "target": target,
            "top_ports": int(args.get("top_ports", 100)),
            "timeout_seconds": int(args.get("timeout_seconds", 60)),
        }

        timeout = payload["timeout_seconds"] + 10
        async with httpx.AsyncClient(timeout=float(timeout)) as client:
            try:
                resp = await client.post(url, json=payload, headers=headers)
            except httpx.TimeoutException as exc:
                raise TimeoutError(f"Runner connection timed out: {exc}") from exc

            if resp.status_code == 504:
                raise TimeoutError("Scanner execution timed out in runner")
            if resp.status_code != 200:
                raise RuntimeError(f"Runner returned HTTP {resp.status_code}: {resp.text}")

            data = resp.json()
            if data.get("status") == "failed" and data.get("exit_code") != 0:
                raise RuntimeError(
                    f"Nmap exited with code {data.get('exit_code')}: {data.get('stderr')}"
                )

            stdout = data.get("stdout", "")
            return stdout.encode("utf-8")

    def parse(self, raw_output: bytes, tool_run_id: str | None = None) -> list[RawObservation]:
        """Parse Nmap XML output using defusedxml into RawObservation list."""
        if not raw_output or not raw_output.strip():
            return []

        try:
            root = ET.fromstring(raw_output)
        except Exception as exc:
            raise ValueError(f"Failed to parse Nmap XML: {exc}") from exc

        run_id = tool_run_id or ""
        now = utc_now()
        observations: list[RawObservation] = []

        for host_elem in root.findall("host"):
            # Check host status
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            # Identify target
            target_addr = ""
            for addr_elem in host_elem.findall("address"):
                if addr_elem.get("addrtype") in ("ipv4", "ipv6"):
                    target_addr = addr_elem.get("addr", "")
                    break
            if not target_addr:
                addr_elem = host_elem.find("address")
                if addr_elem is not None:
                    target_addr = addr_elem.get("addr", "")

            hostname = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name", "")
                    if name:
                        hostname = name
                        break

            identifier = target_addr or hostname or "unknown"

            # Parse open ports
            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id = int(port_elem.get("portid", "0"))
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name") if service_elem is not None else None
                product = service_elem.get("product") if service_elem is not None else None
                version = service_elem.get("version") if service_elem is not None else None
                extrainfo = service_elem.get("extrainfo") if service_elem is not None else None

                version_parts = [p for p in (product, version, extrainfo) if p]
                service_version = " ".join(version_parts) if version_parts else None

                xpath_ref = f"//host[address[@addr='{identifier}']]/ports/port[@portid='{port_id}']"

                # Port exposure observation
                service_display = service_name or "unknown"
                obs = RawObservation(
                    tool=self.name,
                    asset_identifier=identifier,
                    asset_type="host",
                    port=port_id,
                    protocol=protocol,
                    service_name=service_name,
                    service_version=service_version,
                    title=f"Open Port {port_id}/{protocol} ({service_display})",
                    description=(
                        f"Nmap discovered open port {port_id}/{protocol} running service "
                        f"{service_display}"
                        + (f" ({service_version})" if service_version else "")
                        + "."
                    ),
                    severity="info",
                    confidence="high",
                    confidence_score=0.9,
                    category="exposure",
                    raw_ref={
                        "tool_run_id": run_id,
                        "xpath": xpath_ref,
                    },
                    evidence=(
                        f"Host: {identifier}, Port: {port_id}/{protocol}, "
                        f"State: open, Service: {service_display}"
                        + (f", Version: {service_version}" if service_version else "")
                    ),
                    timestamp=now,
                )
                observations.append(obs)

                # Script observations on port
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    output = script_elem.get("output", "")
                    cves = sorted(set(CVE_PATTERN.findall(output)))
                    script_xpath = f"{xpath_ref}/script[@id='{script_id}']"

                    has_vuln = bool(cves) or any(
                        term in script_id.lower() or term in output.lower()
                        for term in ("vulnerable", "cve-", "exploit", "security")
                    )

                    script_obs = RawObservation(
                        tool=self.name,
                        asset_identifier=identifier,
                        asset_type="host",
                        port=port_id,
                        protocol=protocol,
                        service_name=service_name,
                        service_version=service_version,
                        title=f"Nmap Script: {script_id} on Port {port_id}",
                        description=f"Script {script_id} output:\n{output.strip()}",
                        severity="medium" if has_vuln else "info",
                        confidence="high",
                        confidence_score=0.85,
                        category="misconfig" if not cves else "outdated_software",
                        cve_ids=cves,
                        raw_ref={
                            "tool_run_id": run_id,
                            "xpath": script_xpath,
                        },
                        evidence=output.strip(),
                        timestamp=now,
                    )
                    observations.append(script_obs)

            # Host scripts
            hostscript_elem = host_elem.find("hostscript")
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    output = script_elem.get("output", "")
                    cves = sorted(set(CVE_PATTERN.findall(output)))
                    script_xpath = (
                        f"//host[address[@addr='{identifier}']]"
                        f"/hostscript/script[@id='{script_id}']"
                    )

                    script_obs = RawObservation(
                        tool=self.name,
                        asset_identifier=identifier,
                        asset_type="host",
                        title=f"Nmap Host Script: {script_id}",
                        description=f"Host script {script_id} output:\n{output.strip()}",
                        severity="low" if not cves else "medium",
                        confidence="high",
                        confidence_score=0.85,
                        category="exposure" if not cves else "outdated_software",
                        cve_ids=cves,
                        raw_ref={
                            "tool_run_id": run_id,
                            "xpath": script_xpath,
                        },
                        evidence=output.strip(),
                        timestamp=now,
                    )
                    observations.append(script_obs)

        return observations
