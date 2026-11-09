"""Agent orchestrator managing reasoning, state, deduplication guard, and tool execution."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.agent.client import AgentResponse, ChatMessage, LLMClient, get_llm_client
from app.agent.prompts import SYSTEM_PROMPT, TOOL_DEFINITIONS
from app.agent.tools import execute_agent_tool
from app.agent.validation import validate_grounding
from app.events import event_hub
from app.repo.audit import append_audit_event
from app.settings import Settings, get_settings


@dataclass
class AssessmentState:
    """State tracked across reasoning steps for one assessment."""

    assessment_id: str
    completed_steps: list[str] = field(default_factory=list)
    executed_scans: set[tuple[str, str, str]] = field(default_factory=set)
    avoided_repeats: int = 0
    technologies_detected: set[str] = field(default_factory=set)
    hypotheses: list[str] = field(default_factory=list)


class AgentOrchestrator:
    """Orchestrates LLM planning, human-in-the-loop gating, and guarded tool execution."""

    def __init__(
        self,
        client: LLMClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client or get_llm_client(self.settings)
        self.states: dict[str, AssessmentState] = {}

    def get_state(self, assessment_id: str) -> AssessmentState:
        if assessment_id not in self.states:
            self.states[assessment_id] = AssessmentState(assessment_id=assessment_id)
        return self.states[assessment_id]

    async def run_turn(
        self,
        session: Session,
        assessment_id: str,
        user_message: str,
        chat_history: list[ChatMessage] | None = None,
    ) -> tuple[AgentResponse, list[str]]:
        """Execute one complete conversational agent turn with grounding validation."""
        state = self.get_state(assessment_id)
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
        ]
        if chat_history:
            messages.extend(chat_history)
        messages.append(ChatMessage(role="user", content=user_message))

        await event_hub.emit(
            assessment_id,
            "reasoning_note",
            {"message": "Agent reasoning on user goal...", "assessment_id": assessment_id},
        )

        # 1. LLM completion with tools
        response = await self.client.complete(messages, tools=TOOL_DEFINITIONS)

        # 2. Execute any proposed tool calls
        if response.tool_calls:
            for tc in response.tool_calls:
                call_args = dict(tc.arguments)
                call_args["assessment_id"] = assessment_id

                # Deduplication Guard for active scanner runs
                if tc.name in ("run_nmap", "run_nikto", "run_zap"):
                    target_val = call_args.get("target") or call_args.get("url", "")
                    params_key = json.dumps(call_args, sort_keys=True)
                    scan_key = (tc.name, target_val, params_key)

                    if scan_key in state.executed_scans:
                        state.avoided_repeats += 1
                        append_audit_event(
                            session,
                            assessment_id=assessment_id,
                            actor="agent",
                            event_type="agent.duplicate_scan_avoided",
                            detail={
                                "tool": tc.name,
                                "target": target_val,
                                "avoided_repeats": state.avoided_repeats,
                            },
                            outcome="avoided",
                        )
                        await event_hub.emit(
                            assessment_id,
                            "reasoning_note",
                            {
                                "message": f"Duplicate scan avoided for {tc.name} on {target_val}",
                                "avoided_repeats": state.avoided_repeats,
                            },
                        )
                        continue

                    state.executed_scans.add(scan_key)

                # Tool execution event
                await event_hub.emit(
                    assessment_id,
                    "step_started",
                    {"tool": tc.name, "arguments": tc.arguments},
                )

                try:
                    tool_result = await execute_agent_tool(
                        session=session,
                        tool_name=tc.name,
                        args=call_args,
                        settings=self.settings,
                    )
                    if tc.name != "propose_plan":
                        state.completed_steps.append(f"{tc.name}:{call_args.get('target', '')}")
                    await event_hub.emit(
                        assessment_id,
                        "step_finished",
                        {"tool": tc.name, "result": tool_result},
                    )
                except Exception as exc:
                    await event_hub.emit(
                        assessment_id,
                        "step_failed",
                        {"tool": tc.name, "error": str(exc)},
                    )

        # 3. Anti-hallucination validation on final content
        cleaned_content, hallucinations = validate_grounding(
            session=session,
            assessment_id=assessment_id,
            text=response.content,
        )

        response.content = cleaned_content
        return response, hallucinations
