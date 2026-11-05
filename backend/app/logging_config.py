"""Minimal JSON structured logging for backend events."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

_BEARER_VALUE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>['\"]?\b(?:password|passwd|secret|credential|access[_-]?token|"
    r"refresh[_-]?token|token|api[_-]?key|authorization)['\"]?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}&]+)"
)


def redact_sensitive_text(value: str) -> str:
    """Remove common bearer tokens and secret assignments from free-form log text."""
    without_bearer = _BEARER_VALUE.sub(r"\1[REDACTED]", value)
    return _SECRET_ASSIGNMENT.sub(r"\g<prefix>[REDACTED]", without_bearer)


class JsonFormatter(logging.Formatter):
    """Format a small, allowlisted set of log fields as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive_text(record.getMessage()),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging() -> None:
    """Configure root logging with an allowlist-only JSON formatter."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
