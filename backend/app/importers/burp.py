"""Burp Suite XML issues export importer using defusedxml."""

from __future__ import annotations

from urllib.parse import urlparse

import defusedxml.ElementTree as ET

from app.importers.base import BaseImporter, utc_now
from app.models.schemas import RawObservation

SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
}

CONFIDENCE_MAP = {
    "certain": ("high", 0.95),
    "firm": ("medium", 0.75),
    "tentative": ("low", 0.4),
}


class BurpImporter(BaseImporter):
    """Importer for PortSwigger Burp Suite XML issues export."""

    name = "burp"

    def parse_content(
        self, content: bytes, tool_run_id: str | None = None
    ) -> dict[str, list[RawObservation]]:
        """Parse Burp XML issues and map findings grouped by host."""
        if not content or not content.strip():
            return {}

        try:
            root = ET.fromstring(content)
        except Exception as exc:
            raise ValueError(f"Failed to parse Burp XML: {exc}") from exc

        run_id = tool_run_id or ""
        now = utc_now()
        results: dict[str, list[RawObservation]] = {}

        for idx, issue in enumerate(root.findall("issue")):
            host_elem = issue.find("host")
            ip_attr = host_elem.get("ip") if host_elem is not None else ""
            host_text = host_elem.text.strip() if host_elem is not None and host_elem.text else ""

            # Resolve host identifier
            identifier = ip_attr
            if not identifier and host_text:
                if "://" in host_text:
                    parsed = urlparse(host_text)
                    identifier = parsed.hostname or host_text
                else:
                    identifier = host_text

            identifier = identifier or "unknown"
            if identifier not in results:
                results[identifier] = []

            name_elem = issue.find("name")
            name = (
                name_elem.text.strip() if name_elem is not None and name_elem.text else "Burp Issue"
            )

            port_elem = issue.find("port")
            port: int | None = None
            if port_elem is not None and port_elem.text and port_elem.text.isdigit():
                port = int(port_elem.text.strip())

            proto_elem = issue.find("protocol")
            protocol = (
                proto_elem.text.strip() if proto_elem is not None and proto_elem.text else "http"
            )

            sev_elem = issue.find("severity")
            sev_raw = (
                sev_elem.text.strip().lower() if sev_elem is not None and sev_elem.text else "low"
            )
            severity = SEVERITY_MAP.get(sev_raw, "low")

            conf_elem = issue.find("confidence")
            conf_raw = (
                conf_elem.text.strip().lower()
                if conf_elem is not None and conf_elem.text
                else "firm"
            )
            confidence, conf_score = CONFIDENCE_MAP.get(conf_raw, ("medium", 0.7))

            path_elem = issue.find("path")
            path = path_elem.text.strip() if path_elem is not None and path_elem.text else None

            loc_elem = issue.find("location")
            location = loc_elem.text.strip() if loc_elem is not None and loc_elem.text else None

            detail_elem = issue.find("issueDetail")
            detail = (
                detail_elem.text.strip() if detail_elem is not None and detail_elem.text else ""
            )

            bg_elem = issue.find("issueBackground")
            bg = bg_elem.text.strip() if bg_elem is not None and bg_elem.text else ""

            desc = f"{detail}\n\n{bg}".strip() if detail or bg else name

            rem_elem = issue.find("remediationDetail") or issue.find("remediationBackground")
            solution = rem_elem.text.strip() if rem_elem is not None and rem_elem.text else None

            # Evidence from request/response
            evidence_parts: list[str] = []
            req_elem = issue.find("requestresponse/request")
            if req_elem is not None and req_elem.text:
                evidence_parts.append(f"Request: {req_elem.text[:500]}")
            resp_elem = issue.find("requestresponse/response")
            if resp_elem is not None and resp_elem.text:
                evidence_parts.append(f"Response: {resp_elem.text[:500]}")
            evidence = "\n".join(evidence_parts) if evidence_parts else detail or name

            # Category
            category = "misconfig"
            name_lower = name.lower()
            if any(
                k in name_lower
                for k in (
                    "xss",
                    "cross-site",
                    "scripting",
                    "sql",
                    "csrf",
                    "injection",
                    "traversal",
                    "ssrf",
                )
            ):
                category = "owasp_top10"
            elif any(k in name_lower for k in ("exposure", "disclosure", "leak")):
                category = "exposure"

            serial = issue.find("serialNumber")
            issue_id = serial.text.strip() if serial is not None and serial.text else str(idx)
            xpath_ref = f"//issues/issue[{idx + 1}][serialNumber='{issue_id}']"

            obs = RawObservation(
                tool=self.name,
                asset_identifier=identifier,
                asset_type="web_application",
                port=port,
                protocol=protocol,
                service_name=protocol,
                title=f"Burp: {name}",
                description=desc,
                severity=severity,
                confidence=confidence,
                confidence_score=conf_score,
                category=category,
                url=location or path,
                raw_ref={"tool_run_id": run_id, "xpath": xpath_ref},
                evidence=evidence,
                solution=solution,
                timestamp=now,
            )
            results[identifier].append(obs)

        return results
