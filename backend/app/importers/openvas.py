"""OpenVAS / Greenbone XML report importer using defusedxml."""

from __future__ import annotations

import re

import defusedxml.ElementTree as ET

from app.importers.base import BaseImporter, utc_now
from app.models.schemas import RawObservation

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def score_to_severity(score: float | None, threat: str | None = None) -> str:
    """Map CVSS/severity score or threat level to common severity scale."""
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"
    if threat:
        t = threat.lower()
        if "high" in t:
            return "high"
        if "medium" in t:
            return "medium"
        if "low" in t:
            return "low"
    return "info"


class OpenVasImporter(BaseImporter):
    """Importer for Greenbone / OpenVAS XML reports."""

    name = "openvas"

    def parse_content(
        self, content: bytes, tool_run_id: str | None = None
    ) -> dict[str, list[RawObservation]]:
        """Parse OpenVAS XML report and map findings grouped by host."""
        if not content or not content.strip():
            return {}

        try:
            root = ET.fromstring(content)
        except Exception as exc:
            raise ValueError(f"Failed to parse OpenVAS XML: {exc}") from exc

        run_id = tool_run_id or ""
        now = utc_now()
        results: dict[str, list[RawObservation]] = {}

        results_elem = root.find("results")
        if results_elem is None:
            results_elem = root

        for idx, res in enumerate(results_elem.findall("result")):
            host_elem = res.find("host")
            host = host_elem.text.strip() if host_elem is not None and host_elem.text else "unknown"

            if host not in results:
                results[host] = []

            name_elem = res.find("name")
            name = (
                name_elem.text.strip()
                if name_elem is not None and name_elem.text
                else "OpenVAS Result"
            )

            port_elem = res.find("port")
            port_val = port_elem.text.strip() if port_elem is not None and port_elem.text else ""
            port: int | None = None
            protocol: str | None = "tcp"

            if "/" in port_val:
                parts = port_val.split("/")
                if parts[0].isdigit():
                    port = int(parts[0])
                protocol = parts[1].lower() if len(parts) > 1 else "tcp"
            elif port_val.isdigit():
                port = int(port_val)

            # Severity / Score
            sev_elem = res.find("severity")
            threat_elem = res.find("threat")
            score: float | None = None
            if sev_elem is not None and sev_elem.text:
                try:
                    score = float(sev_elem.text.strip())
                except ValueError:
                    pass
            threat = (
                threat_elem.text.strip() if threat_elem is not None and threat_elem.text else None
            )
            severity = score_to_severity(score, threat)

            # NVT details
            nvt_elem = res.find("nvt")
            cves: list[str] = []
            if nvt_elem is not None:
                cve_elem = nvt_elem.find("cve")
                if cve_elem is not None and cve_elem.text:
                    cves.extend(CVE_PATTERN.findall(cve_elem.text))
            cves = sorted(set(cves))

            desc_elem = res.find("description")
            desc = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else name

            sol_elem = res.find("solution")
            solution = sol_elem.text.strip() if sol_elem is not None and sol_elem.text else None

            category = "misconfig"
            if cves:
                category = "outdated_software"

            res_id = res.get("id", str(idx))
            xpath_ref = f"//results/result[@id='{res_id}']"

            obs = RawObservation(
                tool=self.name,
                asset_identifier=host,
                asset_type="host",
                port=port,
                protocol=protocol,
                title=f"OpenVAS: {name}",
                description=desc,
                severity=severity,
                confidence="high",
                confidence_score=0.8,
                category=category,
                cve_ids=cves,
                cvss_score=score,
                raw_ref={"tool_run_id": run_id, "xpath": xpath_ref},
                evidence=desc,
                solution=solution,
                timestamp=now,
            )
            results[host].append(obs)

        return results
