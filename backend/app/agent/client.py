"""Provider-neutral LLM client interface and mock implementation for deterministic testing."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.settings import Settings, get_settings


@dataclass
class ChatMessage:
    role: str
    content: str
    tool_call_id: str | None = None
    name: str | None = None
    tool_calls: list[ToolCall] | None = None


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class AgentResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""


class LLMClient(ABC):
    """Abstract interface for LLM completions."""

    @abstractmethod
    async def complete(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentResponse:
        """Generate a response given conversational context and optional tool schemas."""
        ...


class MockLLMClient(LLMClient):
    """Replays canned responses for deterministic offline pytest runs."""

    def __init__(self, responses: list[AgentResponse] | None = None) -> None:
        self.responses: list[AgentResponse] = list(responses or [])
        self.call_history: list[list[ChatMessage]] = []

    def set_responses(self, responses: list[AgentResponse]) -> None:
        self.responses = list(responses)

    def queue_response(self, response: AgentResponse) -> None:
        self.responses.append(response)

    async def complete(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentResponse:
        self.call_history.append(list(messages))
        if self.responses:
            return self.responses.pop(0)
        return AgentResponse(
            content="[OBSERVED] Assessment scope analyzed. Ready to proceed.",
            model="mock-vapt-llm",
        )


class OpenAICompatibleClient(LLMClient):
    """Calls OpenAI-compatible HTTP API endpoints (OpenAI, Anthropic proxy, vLLM, Ollama)."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        self.api_key = api_key
        self.model = model or "gpt-4o"
        self.base_url = base_url.rstrip("/")

    async def complete(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentResponse:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "vapt-agent/1.0",
        }
        payload_messages = []
        for m in messages:
            item: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_call_id:
                item["tool_call_id"] = m.tool_call_id
            if m.name:
                item["name"] = m.name
            if getattr(m, "tool_calls", None):
                item["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in m.tool_calls
                ]
            payload_messages.append(item)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": payload_messages,
        }
        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            if resp.status_code != 200:
                if tools and resp.status_code == 400 and "tool" in resp.text.lower():
                    # Fallback to direct conversational completion if tool format failed
                    retry_payload = dict(payload)
                    retry_payload.pop("tools", None)
                    resp = await client.post(
                        f"{self.base_url}/chat/completions",
                        json=retry_payload,
                        headers=headers,
                    )
                if resp.status_code != 200:
                    raise RuntimeError(f"LLM API error ({resp.status_code}): {resp.text}")

            data = resp.json()
            choice = data["choices"][0]["message"]
            content = choice.get("content") or ""

            tool_calls: list[ToolCall] = []
            for tc in choice.get("tool_calls", []):
                call_id = tc.get("id", "")
                fn_name = tc.get("function", {}).get("name", "")
                fn_args_str = tc.get("function", {}).get("arguments", "{}")
                try:
                    fn_args = json.loads(fn_args_str)
                except Exception:
                    fn_args = {}
                tool_calls.append(ToolCall(id=call_id, name=fn_name, arguments=fn_args))

            return AgentResponse(
                content=content,
                tool_calls=tool_calls,
                model=data.get("model", self.model),
            )


def get_llm_client(settings: Settings | None = None) -> LLMClient:
    """Return configured LLM provider or MockLLMClient if unconfigured or in tests."""
    import os

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return MockLLMClient()

    s = settings or get_settings()
    api_key = s.llm_api_key.get_secret_value()
    provider = (s.llm_provider or "").lower()
    if not api_key or provider == "mock":
        return MockLLMClient()

    base_url = getattr(s, "llm_base_url", "")
    if provider == "groq":
        base_url = base_url or "https://api.groq.com/openai/v1"
        model = s.llm_model or "openai/gpt-oss-120b"
    else:
        base_url = base_url or "https://api.openai.com/v1"
        model = s.llm_model or "gpt-4o"

    return OpenAICompatibleClient(api_key=api_key, model=model, base_url=base_url)
