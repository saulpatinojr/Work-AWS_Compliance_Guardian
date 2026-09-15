"""Structured, redacted audit sinks."""

from __future__ import annotations

from dataclasses import replace
from typing import TextIO, cast

from .contracts import AuditEvent, JsonValue
from .ports import AuditSink

_SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "authorization",
    "accesskey",
    "credential",
    "privatekey",
    "cookie",
    "audio",
    "transcript",
)


def _redact(value: JsonValue, key: str | None = None) -> JsonValue:
    if key is not None:
        normalized_key = "".join(character for character in key.casefold() if character.isalnum())
        if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
            return "[REDACTED]"
    if isinstance(value, dict):
        return {item_key: _redact(item, item_key) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class JsonLineAuditSink(AuditSink):
    """Writes one redacted JSON object per line to a configured sink."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def record(self, event: AuditEvent) -> None:
        redacted_details = cast(dict[str, JsonValue], _redact(dict(event.details)))
        self._stream.write(replace(event, details=redacted_details).to_json())
        self._stream.write("\n")
        self._stream.flush()
