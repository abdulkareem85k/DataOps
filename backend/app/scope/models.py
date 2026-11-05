"""Deterministic scope-rule and decision types. No LLM involvement."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ActionClass = Literal["discovery", "vuln_scan", "web_scan", "active_validation"]
ScopeOutcome = Literal["allowed", "denied"]


class ScopeRules(BaseModel):
    """Validated in-memory representation of an assessment's scope document."""

    model_config = ConfigDict(extra="forbid")

    allowed_targets: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_action_classes: list[ActionClass] = Field(default_factory=list)
    rate_limit_max: int | None = Field(default=None, ge=1)
    rate_limit_window_seconds: int | None = Field(default=None, ge=1)
    window_start: datetime | None = None
    window_end: datetime | None = None
    notes: str | None = None


class Decision(BaseModel):
    """Result of a deterministic scope check."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    outcome: ScopeOutcome
    reason: str
    rule_id: str | None = None

    @classmethod
    def allow(cls, reason: str, rule_id: str | None = None) -> Decision:
        """Construct an allowed decision."""
        return cls(allowed=True, outcome="allowed", reason=reason, rule_id=rule_id)

    @classmethod
    def deny(cls, reason: str, rule_id: str | None = None) -> Decision:
        """Construct a denied decision."""
        return cls(allowed=False, outcome="denied", reason=reason, rule_id=rule_id)
