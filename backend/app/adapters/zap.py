"""OWASP ZAP live scanner adapter using ZAP REST API."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlparse

import httpx

from app.adapters.base import ToolAdapter, utc_now
from app.models.schemas import RawObservation
from app.scope.enforcement import ScopeToken


class ZapAdapter(ToolAdapter):
    """Live OWASP ZAP adapter with passive scan default and gated active scan."""

    name = "zap"
    mode = "live"
    capabilities = ["spider", "passive_scan", "active_scan"]

    async def check_availability(self) -> bool:
        """Check if ZAP REST API is reachable."""
        url = f"{self.settings.zap_url.rstrip('/')}/JSON/core/view/version/"
        params = {}
        api_key = self.settings.zap_api_key.get_secret_value()
        if api_key:
            params["apikey"] = api_key
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, params=params)
                return resp.status_code == 200
        except Exception:
            return False

    async def execute(
        self,
        target: str,
        args: dict[str, Any],
        token: ScopeToken,
    ) -> bytes:
        """Run spider and passive scan (or active scan if explicitly enabled)."""
        active_scan_requested = bool(args.get("active_scan", False))
        if active_scan_requested and not self.settings.enable_zap_active_scan:
            raise PermissionError(
                "ZAP active scanning is disabled by configuration (ENABLE_ZAP_ACTIVE_SCAN=false)."
            )

        api_key = self.settings.zap_api_key.get_secret_value()
        base_zap_url = self.settings.zap_url.rstrip("/")

        target_url = target
        if not target.startswith("http://") and not target.startswith("https://"):
            target_url = f"http://{target}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"X-ZAP-API-Key": api_key} if api_key else {}

            # 1. Start spider scan
            spider_start_url = f"{base_zap_url}/JSON/spider/action/scan/"
            resp = await client.get(
                spider_start_url,
                params={"url": target_url, "apikey": api_key},
                headers=headers,
            )
            if resp.status_code != 200:
                raise RuntimeError(f"ZAP spider failed to start: {resp.text}")
            scan_id = resp.json().get("scan", "0")

            # 2. Wait for spider to reach 100%
            max_spider_wait = int(args.get("spider_timeout", 60))
            for _ in range(max_spider_wait // 2):
                await asyncio.sleep(2)
                status_resp = await client.get(
                    f"{base_zap_url}/JSON/spider/view/status/",
                    params={"scanId": scan_id, "apikey": api_key},
                    headers=headers,
                )
                if status_resp.status_code == 200:
                    status = status_resp.json().get("status", "0")
                    if status == "100":
                        break

            # 3. Wait for passive scan records to drain
            max_pscan_wait = int(args.get("pscan_timeout", 30))
            for _ in range(max_pscan_wait // 2):
                await asyncio.sleep(2)
                pscan_resp = await client.get(
                    f"{base_zap_url}/JSON/pscan/view/recordsToScan/",
                    params={"apikey": api_key},
                    headers=headers,
                )
                if pscan_resp.status_code == 200:
                    remaining = pscan_resp.json().get("recordsToScan", "0")
                    if str(remaining) == "0":
                        break

            # 4. If active scan requested and permitted:
            if active_scan_requested and self.settings.enable_zap_active_scan:
                ascan_start_url = f"{base_zap_url}/JSON/ascan/action/scan/"
                ascan_resp = await client.get(
                    ascan_start_url,
                    params={"url": target_url, "apikey": api_key},
                    headers=headers,
                )
                if ascan_resp.status_code == 200:
                    ascan_id = ascan_resp.json().get("scan", "0")
                    max_ascan_wait = int(args.get("ascan_timeout", 90))
                    for _ in range(max_ascan_wait // 3):
                        await asyncio.sleep(3)
                        st_resp = await client.get(
                            f"{base_zap_url}/JSON/ascan/view/status/",
                            params={"scanId": ascan_id, "apikey": api_key},
                            headers=headers,
                        )
                        if st_resp.status_code == 200:
                            if st_resp.json().get("status", "0") == "100":
                                break

            # 5. Fetch all alerts
            alerts_url = f"{base_zap_url}/JSON/core/view/alerts/"
            alerts_resp = await client.get(
                alerts_url,
                params={"baseurl": target_url, "apikey": api_key},
                headers=headers,
            )
            if alerts_resp.status_code != 200:
                raise RuntimeError(f"ZAP alerts query failed: {alerts_resp.text}")

            return alerts_resp.content

    def parse(self, raw_output: bytes, tool_run_id: str | None = None) -> list[RawObservation]:
        """Parse ZAP JSON alerts into RawObservation list."""
        if not raw_output or not raw_output.strip():
            return []

        try:
            data = json.loads(raw_output.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise ValueError(f"Failed to parse ZAP JSON: {exc}") from exc

        alerts = data.get("alerts", [])
        if isinstance(data, list):
            alerts = data

        run_id = tool_run_id or ""
        now = utc_now()
        observations: list[RawObservation] = []

        risk_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
        }

        conf_map = {
            "high": ("high", 0.9),
            "medium": ("medium", 0.7),
            "low": ("low", 0.4),
            "false positive": ("low", 0.1),
            "falsepositive": ("low", 0.1),
        }

        for idx, alert in enumerate(alerts):
            name = alert.get("name") or alert.get("alert") or "ZAP Finding"
            risk_raw = str(alert.get("risk", "Low")).lower()
            severity = risk_map.get(risk_raw, "low")

            conf_raw = str(alert.get("confidence", "Medium")).lower()
            confidence_level, confidence_score = conf_map.get(conf_raw, ("medium", 0.5))

            cwe_id_raw = str(alert.get("cweid", "")).strip()
            cwe_ids: list[str] = []
            if cwe_id_raw and cwe_id_raw.isdigit() and int(cwe_id_raw) > 0:
                cwe_ids.append(f"CWE-{cwe_id_raw}")

            url_val = alert.get("url", "")
            parsed = urlparse(url_val) if url_val else None
            host = parsed.hostname if parsed else "unknown"
            port = (
                parsed.port
                if parsed and parsed.port
                else (443 if parsed and parsed.scheme == "https" else 80)
            )
            protocol = parsed.scheme if parsed else "http"

            desc = alert.get("description", "")
            param = alert.get("param", "")
            evidence = alert.get("evidence", "") or alert.get("attack", "")
            solution = alert.get("solution", "")
            reference = alert.get("reference", "")

            # Category deduction
            category = "misconfig"
            if cwe_ids and any(cwe in ("CWE-79", "CWE-89", "CWE-352", "CWE-22") for cwe in cwe_ids):
                category = "owasp_top10"
            elif any(k in name.lower() for k in ("xss", "injection", "csrf", "sqli")):
                category = "owasp_top10"

            refs = [r.strip() for r in reference.split("\n") if r.strip()] if reference else []

            obs = RawObservation(
                tool=self.name,
                asset_identifier=host or "unknown",
                asset_type="web_application",
                port=port,
                protocol=protocol,
                service_name=protocol,
                title=f"ZAP: {name}",
                description=desc if desc else name,
                severity=severity,
                confidence=confidence_level,
                confidence_score=confidence_score,
                category=category,
                url=url_val if url_val else None,
                parameter=param if param else None,
                cwe_ids=cwe_ids,
                raw_ref={"tool_run_id": run_id, "json_pointer": f"/alerts/{idx}"},
                evidence=evidence or f"URL: {url_val}, Param: {param}",
                solution=solution if solution else None,
                references=refs,
                timestamp=now,
            )
            observations.append(obs)

        return observations
