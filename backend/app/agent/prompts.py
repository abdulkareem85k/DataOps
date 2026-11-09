"""System prompts, persona instructions, and LLM tool definitions."""

from __future__ import annotations

from typing import Any

SYSTEM_PROMPT = """You are the AI Unified VAPT Agent, an autonomous security assessment
planning and reasoning orchestrator.

### CORE OPERATING RULES:
1. TRUTHFULNESS & GROUNDING:
   - Every factual assertion about an asset, port, service, or vulnerability MUST cite
     a specific finding ID (e.g. FND-0001) or tool run.
   - You MUST prefix factual statements with [OBSERVED] (citable raw data) and all
     hypotheses, explanations, and risk interpretations with [INFERENCE].
   - NEVER fabricate CVEs, CWEs, open ports, or scanner outputs. If a vulnerability is
     not present in stored findings, you MUST NOT claim it exists.

2. SAFETY & SCOPE:
   - You only operate within the registered assessment scope.
   - Active validation, exploit verification, and intrusive scanning NEVER run
     autonomously. You must call request_validation to obtain an authorized human token.
   - You have NO access to arbitrary shell commands, raw sockets, or docker commands.
     You only invoke predefined, typed application tools.

3. REASONING LOOP (Plan -> Approve -> Execute -> Observe -> Reason -> Re-plan):
   - Propose clear, bounded steps with technical rationales.
   - Do not repeat identical scans without a documented reason.
"""

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_scope",
            "description": "List authorized targets, exclusions, and action classes.",
            "parameters": {
                "type": "object",
                "properties": {"assessment_id": {"type": "string", "description": "Assessment ID"}},
                "required": ["assessment_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_assets",
            "description": "Get all discovered assets under this assessment.",
            "parameters": {
                "type": "object",
                "properties": {"assessment_id": {"type": "string", "description": "Assessment ID"}},
                "required": ["assessment_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_services",
            "description": "Get discovered network and web services for a specific asset.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "asset_id": {"type": "string", "description": "Asset ID"},
                },
                "required": ["assessment_id", "asset_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": "Query normalized, correlated security findings with filters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (critical, high, medium, low, info)",
                    },
                    "sort": {
                        "type": "string",
                        "description": "Sort by (risk, severity, first_seen)",
                    },
                },
                "required": ["assessment_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_plan",
            "description": "Propose an ordered plan of assessment steps for approval.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "title": {"type": "string", "description": "Plan title"},
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "Tool name (nmap, nikto, zap, validate)",
                                },
                                "target": {
                                    "type": "string",
                                    "description": "Target IP, hostname, or URL",
                                },
                                "rationale": {
                                    "type": "string",
                                    "description": "Technical reason for this step",
                                },
                                "arguments": {
                                    "type": "object",
                                    "description": "Arguments dictionary",
                                },
                            },
                            "required": ["action", "target", "rationale"],
                        },
                    },
                },
                "required": ["assessment_id", "steps"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nmap",
            "description": "Run an in-scope Nmap discovery or service scan against a target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "target": {"type": "string", "description": "In-scope target IP or hostname"},
                    "top_ports": {
                        "type": "integer",
                        "description": "Number of top ports (100 or 1000)",
                    },
                },
                "required": ["assessment_id", "target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nikto",
            "description": "Run an in-scope Nikto web server scan against an HTTP/HTTPS endpoint.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "url": {"type": "string", "description": "In-scope web target URL"},
                },
                "required": ["assessment_id", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_zap",
            "description": "Run an in-scope OWASP ZAP spider and passive web vulnerability scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "url": {"type": "string", "description": "In-scope target web URL"},
                },
                "required": ["assessment_id", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_validation",
            "description": "Submit human approval request for active validation or testing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "finding_id": {"type": "string", "description": "Finding ID to validate"},
                    "tool": {"type": "string", "description": "Validation tool name"},
                    "target": {"type": "string", "description": "Target address"},
                    "justification": {
                        "type": "string",
                        "description": "Why active validation is necessary",
                    },
                    "risk": {
                        "type": "string",
                        "description": "Risk assessment of the validation check",
                    },
                },
                "required": ["assessment_id", "finding_id", "tool", "target", "justification"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_finding",
            "description": "Record an analyst or AI inference explanation on a finding.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {"type": "string", "description": "Assessment ID"},
                    "finding_id": {"type": "string", "description": "Finding ID"},
                    "status": {"type": "string", "description": "Optional status update"},
                    "inference_text": {
                        "type": "string",
                        "description": "Inference explanation text",
                    },
                },
                "required": ["assessment_id", "finding_id", "inference_text"],
            },
        },
    },
]
