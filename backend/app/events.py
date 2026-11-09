"""In-memory event hub for Server-Sent Events across assessments."""

from __future__ import annotations

import asyncio
from typing import Any


class EventHub:
    """Manages SSE subscribers and dispatches events by assessment_id."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}

    def subscribe(self, assessment_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Register a subscriber queue for an assessment."""
        if assessment_id not in self._subscribers:
            self._subscribers[assessment_id] = set()
        self._subscribers[assessment_id].add(queue)

    def unsubscribe(self, assessment_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Unregister a subscriber queue."""
        if assessment_id in self._subscribers:
            self._subscribers[assessment_id].discard(queue)
            if not self._subscribers[assessment_id]:
                del self._subscribers[assessment_id]

    async def emit(self, assessment_id: str, event: str, data: dict[str, Any]) -> None:
        """Publish an event to all subscribers of the assessment."""
        subscribers = list(self._subscribers.get(assessment_id, set()))
        payload = {"event": event, **data}
        for q in subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass


event_hub = EventHub()
