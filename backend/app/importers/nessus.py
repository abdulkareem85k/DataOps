"""Nessus .nessus v2 XML report importer using defusedxml."""

from __future__ import annotations

import re

import defusedxml.ElementTree as ET

from app.importers.base import BaseImporter, utc_now
from app.models.schemas import RawObservation

SEVERITY_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NessusImporter(BaseImporter):
    """Importer for Tenable Nessus v2 XML exports."""

    name = "nessus"

    def parse_content(
        self, content: bytes, tool_run_id: str | None = None
    ) -> dict[str, list[RawObservation]]:
        """Parse Nessus XML and map findings grouped by host."""
        if not content or not content.strip():
            return {}

        try:
            root = ET.fromstring(content)
        except Exception as exc:
            raise ValueError(f"Failed to parse Nessus XML: {exc}") from exc

        run_id = tool_run_id or ""
        now = utc_now()
        results: dict[str, list[RawObservation]] = {}

        report = root.find("Report")
        if report is None:
            report = root

        for host_elem in report.findall("ReportHost"):
            host_name = host_elem.get("name", "")
            ip_val = ""

            props = host_elem.find("HostProperties")
            if props is not None:
                for tag in props.findall("tag"):
                    if tag.get("name") == "host-ip" and tag.text:
                        ip_val = tag.text.strip()
                        break

            identifier = ip_val or host_name or "unknown"
            if identifier not in results:
                results[identifier] = []

            for idx, item in enumerate(host_elem.findall("ReportItem")):
                port_str = item.get("port", "0")
                port = int(port_str) if port_str.isdigit() and int(port_str) > 0 else None
                protocol = item.get("protocol") or "tcp"
                svc_name = item.get("svc_name")
                sev_raw = item.get("severity", "0")
                severity = SEVERITY_MAP.get(str(sev_raw), "info")

                plugin_id = item.get("pluginID", "")
                plugin_name = item.get("pluginName") or "Nessus Finding"

                # Extract CVEs
                cves: list[str] = []
                for cve_elem in item.findall("cve"):
                    if cve_elem.text:
                        cves.extend(CVE_PATTERN.findall(cve_elem.text))
                cves = sorted(set(cves))

                # CVSS
                cvss_score: float | None = None
                cvss_elem = item.find("cvss_base_score")
                if cvss_elem is not None and cvss_elem.text:
                    try:
                        cvss_score = float(cvss_elem.text.strip())
                    except ValueError:
                        pass

                cvss_vector: str | None = None
                vec_elem = item.find("cvss3_vector") or item.find("cvss_vector")
                if vec_elem is not None and vec_elem.text:
                    cvss_vector = vec_elem.text.strip()

                desc_elem = item.find("description")
                desc = (
                    desc_elem.text.strip()
                    if desc_elem is not None and desc_elem.text
                    else plugin_name
                )

                output_elem = item.find("plugin_output")
                output = (
                    output_elem.text.strip() if output_elem is not None and output_elem.text else ""
                )

                sol_elem = item.find("solution")
                solution = sol_elem.text.strip() if sol_elem is not None and sol_elem.text else None

                # Category
                category = "misconfig"
                if cves:
                    category = "outdated_software"
                elif any(
                    k in plugin_name.lower() for k in ("exposure", "leak", "information disclosure")
                ):
                    category = "exposure"

                xpath_ref = (
                    f"//ReportHost[@name='{host_name}']"
                    f"/ReportItem[@pluginID='{plugin_id}'][{idx + 1}]"
                )

                obs = RawObservation(
                    tool=self.name,
                    asset_identifier=identifier,
                    asset_type="host",
                    port=port,
                    protocol=protocol,
                    service_name=svc_name,
                    title=f"Nessus: {plugin_name}",
                    description=desc,
                    severity=severity,
                    confidence="high",
                    confidence_score=0.85,
                    category=category,
                    cve_ids=cves,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    raw_ref={"tool_run_id": run_id, "xpath": xpath_ref},
                    evidence=output or desc,
                    solution=solution,
                    timestamp=now,
                )
                results[identifier].append(obs)

        return results
