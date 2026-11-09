"""Tool runs and SSE events HTTP endpoints."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_session
from app.events import event_hub
from app.models.schemas import ToolRunRead
from app.repo.assessments import get_assessment
from app.repo.common import RecordNotFound
from app.repo.tool_runs import list_tool_runs

router = APIRouter()
DbSession = Annotated[Session, Depends(get_session)]


@router.get("/assessments/{assessment_id}/tool-runs", response_model=list[ToolRunRead])
def get_tool_runs_endpoint(
    assessment_id: str,
    session: DbSession,
) -> list[ToolRunRead]:
    """List tool runs for an assessment."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc
    return list_tool_runs(session, assessment_id)


@router.get("/assessments/{assessment_id}/events")
async def events_endpoint(
    assessment_id: str,
    session: DbSession,
) -> StreamingResponse:
    """Stream live events and status transitions using Server-Sent Events (SSE)."""
    try:
        get_assessment(session, assessment_id)
    except RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="assessment not found") from exc

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        event_hub.subscribe(assessment_id, queue)
        try:
            # Initial ping/connection handshake
            yield f"event: connected\ndata: {json.dumps({'assessment_id': assessment_id})}\n\n"
            while True:
                try:
                    # Wait for next event or send keepalive ping every 15s
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
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
