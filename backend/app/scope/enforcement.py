"""Base guard that every tool runner must call before execution."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.scope.engine import Resolver, ScopeDenied, check_action
from app.scope.models import ActionClass, Decision
from app.settings import Settings


class ScopeGuardError(RuntimeError):
    """Raised when a tool attempts to run without a successful require_scope call."""


@dataclass(frozen=True)
class ScopeToken:
    """Capability created only by require_scope after a successful allow decision."""

    assessment_id: str
    tool: str
    target: str
    decision: Decision
    _marker: str


_MARKER = "require_scope:v1"


def require_scope(
    session: Session,
    assessment_id: str,
    tool: str,
    target: str,
    action_class: ActionClass | str,
    args: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    resolve: Resolver | None = None,
    redirects: Sequence[str] | None = None,
    now: datetime | None = None,
) -> ScopeToken:
    """Check scope and return a token the tool runner must present before running."""
    decision = check_action(
        session,
        assessment_id,
        tool,
        target,
        action_class,
        args,
        settings=settings,
        resolve=resolve,
        redirects=redirects,
        now=now,
    )
    if not decision.allowed:
        raise ScopeDenied(decision)
    return ScopeToken(
        assessment_id=assessment_id,
        tool=tool,
        target=target,
        decision=decision,
        _marker=_MARKER,
    )


def run_tool(token: ScopeToken | None, execute: object) -> object:
    """Execute a tool payload only when require_scope issued a valid token."""
    if not isinstance(token, ScopeToken) or token._marker != _MARKER or not token.decision.allowed:
        raise ScopeGuardError("tool cannot run without require_scope")
    if callable(execute):
        return execute()
    return execute
