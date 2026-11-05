"""Deterministic scope engine package."""

from app.scope.enforcement import ScopeGuardError, ScopeToken, require_scope, run_tool
from app.scope.engine import (
    ScopeDenied,
    ScopeRegistrationError,
    check_action,
    register_scope,
    revalidate_at_execution,
)
from app.scope.models import Decision, ScopeRules
from app.scope.sanitize import ArgsSanitizerError, sanitize_args, sanitize_nmap_args

__all__ = [
    "ArgsSanitizerError",
    "Decision",
    "ScopeDenied",
    "ScopeGuardError",
    "ScopeRegistrationError",
    "ScopeRules",
    "ScopeToken",
    "check_action",
    "register_scope",
    "require_scope",
    "revalidate_at_execution",
    "run_tool",
    "sanitize_args",
    "sanitize_nmap_args",
]
