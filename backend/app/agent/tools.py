"""Predefined typed agent tools for AI orchestrator execution."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.adapters.nikto import NiktoAdapter
from app.adapters.nmap import NmapAdapter
from app.adapters.zap import ZapAdapter
from app.models.orm import Approval, Plan, PlanStep
from app.repo.assets import list_assets, list_services
from app.repo.audit import append_audit_event
from app.repo.common import new_id
from app.repo.findings import list_findings, update_finding
from app.repo.scope import get_scope_rules
from app.repo.tool_runs import list_tool_runs
from app.settings import Settings, get_settings


async def execute_agent_tool(
    session: Session,
    tool_name: str,
    args: dict[str, Any],
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Execute a single typed agent tool with scope checks and audit logging."""
    effective_settings = settings or get_settings()
    assessment_id = args.get("assessment_id", "")

    if tool_name == "list_scope":
        rules = get_scope_rules(session, assessment_id)
        return {
            "allowed_targets": rules.allowed_targets,
            "exclusions": rules.exclusions,
            "allowed_tools": rules.allowed_tools,
            "allowed_action_classes": rules.allowed_action_classes,
        }

    if tool_name == "get_assets":
        assets = list_assets(session, assessment_id)
        return {"assets": [a.model_dump(mode="json") for a in assets]}

    if tool_name == "get_services":
        asset_id = args.get("asset_id", "")
        services = list_services(session, asset_id)
        return {"services": [s.model_dump(mode="json") for s in services]}

    if tool_name == "get_findings":
        severity = args.get("severity")
        sort = args.get("sort", "risk")
        findings = list_findings(session, assessment_id, sort=sort, severity=severity)
        return {
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.tool_severity,
                    "risk_score": f.risk_score,
                    "risk_band": f.risk_band,
                    "cve_ids": f.cve_ids,
                    "cwe_ids": f.cwe_ids,
                    "status": f.status,
                    "source_tools": f.source_tools,
                }
                for f in findings[:20]  # bounded list
            ],
        }

    if tool_name == "get_tool_status":
        runs = list_tool_runs(session, assessment_id)
        return {
            "tool_runs": [
                {
                    "id": r.id,
                    "tool": r.tool,
                    "status": r.status,
                    "started_at": str(r.started_at),
                    "finished_at": str(r.finished_at),
                }
                for r in runs
            ]
        }

    if tool_name == "propose_plan":
        title = args.get("title", "Assessment Plan")
        steps = args.get("steps", [])
        plan = Plan(
            id=new_id("PLN"),
            assessment_id=assessment_id,
            title=title,
            content={"steps": steps},
        )
        session.add(plan)
        session.flush()

        for idx, s in enumerate(steps):
            step_row = PlanStep(
                id=new_id("STP"),
                plan_id=plan.id,
                position=idx,
                action=s.get("action", "scan"),
                arguments={
                    "target": s.get("target"),
                    "rationale": s.get("rationale"),
                    **(s.get("arguments") or {}),
                },
                status="pending",
            )
            session.add(step_row)

        append_audit_event(
            session,
            assessment_id=assessment_id,
            actor="agent",
            event_type="agent.plan_proposed",
            detail={"plan_id": plan.id, "title": title, "steps_count": len(steps)},
            outcome="proposed",
        )
        session.flush()
        return {"plan_id": plan.id, "title": title, "steps_count": len(steps)}

    if tool_name == "run_nmap":
        target = args.get("target", "")
        top_ports = args.get("top_ports", 100)
        adapter = NmapAdapter(settings=effective_settings)
        tool_run, observations = await adapter.run(
            session=session,
            assessment_id=assessment_id,
            target=target,
            action_class="discovery",
            args={"top_ports": top_ports},
        )
        return {
            "tool_run_id": tool_run.id,
            "status": tool_run.status,
            "discovered_observations": len(observations),
        }

    if tool_name == "run_nikto":
        url = args.get("url", "")
        adapter = NiktoAdapter(settings=effective_settings)
        tool_run, observations = await adapter.run(
            session=session,
            assessment_id=assessment_id,
            target=url,
            action_class="web_scan",
            args={},
        )
        return {
            "tool_run_id": tool_run.id,
            "status": tool_run.status,
            "discovered_observations": len(observations),
        }

    if tool_name == "run_zap":
        url = args.get("url", "")
        adapter = ZapAdapter(settings=effective_settings)
        tool_run, observations = await adapter.run(
            session=session,
            assessment_id=assessment_id,
            target=url,
            action_class="web_scan",
            args={"active_scan": False},
        )
        return {
            "tool_run_id": tool_run.id,
            "status": tool_run.status,
            "discovered_observations": len(observations),
        }

    if tool_name == "request_validation":
        finding_id = args.get("finding_id", "")
        tool = args.get("tool", "metasploit")
        target = args.get("target", "")
        justification = args.get("justification", "")
        risk = args.get("risk", "Intrusive payload verification")

        approval = Approval(
            id=new_id("APR"),
            assessment_id=assessment_id,
            action=f"validate:{finding_id}:{tool}:{target}",
            requested_by="ai-agent",
            status="pending",
            reason=f"Justification: {justification} | Risk: {risk}",
        )
        session.add(approval)
        session.flush()

        append_audit_event(
            session,
            assessment_id=assessment_id,
            actor="agent",
            event_type="agent.validation_requested",
            detail={
                "approval_id": approval.id,
                "finding_id": finding_id,
                "tool": tool,
                "target": target,
                "justification": justification,
            },
            outcome="pending_approval",
        )
        return {
            "approval_id": approval.id,
            "status": "pending_approval",
            "message": "Validation request queued for human analyst approval.",
        }

    if tool_name == "update_finding":
        finding_id = args.get("finding_id", "")
        status = args.get("status")
        inference_text = args.get("inference_text", "")
        updated = update_finding(
            session,
            finding_id,
            status=status,
            inference_evidence=inference_text,
        )
        return {"finding_id": updated.id, "status": updated.status}

    raise ValueError(f"Unknown agent tool: {tool_name}")
