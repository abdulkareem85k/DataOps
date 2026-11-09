"""Agent conversation, planning, and streaming HTTP endpoints."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.client import ChatMessage as DomainChatMessage
from app.agent.orchestrator import AgentOrchestrator
from app.db import get_session
from app.events import event_hub
from app.models.orm import ChatMessage, Plan, PlanStep
from app.repo.assessments import get_assessment
from app.repo.audit import append_audit_event
from app.repo.common import RecordNotFound, new_id
from app.settings import Settings, get_settings

router = APIRouter()
DbSession = Annotated[Session, Depends(get_session)]

_orchestrator: AgentOrchestrator | None = None


def get_orchestrator(settings: Settings | None = None) -> AgentOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator(settings=settings)
    return _orchestrator


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)


class PlanApproveRequest(BaseModel):
    plan_id: str
    action: str = Field(default="approve", pattern="^(approve|reject)$")
    reason: str | None = None


@router.post("/assessments/{assessment_id}/chat")
async def chat_endpoint(
    assessment_id: str,
    payload: ChatRequest,
    session: DbSession,
    request: Request,
) -> dict[str, Any]:
    """Submit analyst message to AI agent for planning and autonomous execution."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    # Persist user chat message
    user_row = ChatMessage(
        id=new_id("MSG"),
        assessment_id=assessment_id,
        role="user",
        content=payload.message,
    )
    session.add(user_row)
    session.flush()

    # Retrieve prior chat history
    prior_rows = (
        session.execute(
            select(ChatMessage)
            .where(ChatMessage.assessment_id == assessment_id)
            .order_by(ChatMessage.created_at.asc())
        )
        .scalars()
        .all()
    )
    domain_history = [DomainChatMessage(role=r.role, content=r.content) for r in prior_rows]

    settings = getattr(request.app.state, "settings", None) or get_settings()
    orchestrator = get_orchestrator(settings)

    response, hallucinations = await orchestrator.run_turn(
        session=session,
        assessment_id=assessment_id,
        user_message=payload.message,
        chat_history=domain_history,
    )

    if not response.content or not response.content.strip():
        if response.tool_calls:
            tool_names = ", ".join(tc.name for tc in response.tool_calls)
            response.content = (
                f"Executed tool actions: {tool_names}. Assessment findings and logs updated."
            )
        else:
            response.content = "Assessment analyzed. Ready for further instructions."

    # Persist assistant response
    assistant_row = ChatMessage(
        id=new_id("MSG"),
        assessment_id=assessment_id,
        role="assistant",
        content=response.content,
    )
    session.add(assistant_row)
    session.flush()

    state = orchestrator.get_state(assessment_id)
    return {
        "text": response.content,
        "content": response.content,
        "tool_calls": [
            {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in response.tool_calls
        ],
        "hallucinations_detected": hallucinations,
        "avoided_repeats": state.avoided_repeats,
    }


@router.post("/assessments/{assessment_id}/plan/approve")
def approve_plan_endpoint(
    assessment_id: str,
    payload: PlanApproveRequest,
    session: DbSession,
) -> dict[str, Any]:
    """Record human approval or rejection of an agent-proposed assessment plan."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    plan = session.get(Plan, payload.plan_id)
    if plan is None or plan.assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="plan not found")

    steps = session.execute(select(PlanStep).where(PlanStep.plan_id == plan.id)).scalars().all()

    new_status = "approved" if payload.action == "approve" else "rejected"
    for s in steps:
        s.status = new_status

    append_audit_event(
        session,
        assessment_id=assessment_id,
        actor="user",
        event_type=f"plan.{new_status}",
        detail={"plan_id": plan.id, "reason": payload.reason},
        outcome=new_status,
    )
    session.flush()
    return {"plan_id": plan.id, "status": new_status, "steps_count": len(steps)}


@router.get("/assessments/{assessment_id}/agent/stream")
async def agent_stream_endpoint(
    assessment_id: str,
    session: DbSession,
) -> StreamingResponse:
    """Stream live agent planning, reasoning, and step progress over SSE."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        event_hub.subscribe(assessment_id, queue)
        try:
            yield f"event: connected\ndata: {json.dumps({'assessment_id': assessment_id})}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    event_name = payload.pop("event", "message")
                    yield f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            event_hub.unsubscribe(assessment_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
