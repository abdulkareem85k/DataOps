from __future__ import annotations

import json
import logging

from app.logging_config import JsonFormatter


def test_json_formatter_redacts_bearer_and_secret_assignments() -> None:
    message = (
        'request api_key=sk-live-example "access_token": "refresh-secret" '
        "Authorization: Bearer bearer-secret"
    )
    record = logging.LogRecord("test", logging.INFO, __file__, 1, message, (), None)

    formatted = JsonFormatter().format(record)
    payload = json.loads(formatted)

    assert "sk-live-example" not in formatted
    assert "refresh-secret" not in formatted
    assert "bearer-secret" not in formatted
    assert "[REDACTED]" in payload["message"]
    assert set(payload) == {"timestamp", "level", "logger", "message"}
