"""Optional read-only Nova Sonic adapter boundary."""

from __future__ import annotations

from typing import Protocol

from .contracts import VoiceBriefingResult, VoiceStatus


class NovaSonicTransport(Protocol):
    """Transport for a validated bidirectional Nova Sonic session.

    The transport receives only a read-only briefing prompt. It has no
    remediation-tool registry and therefore cannot bypass the Gateway.
    """

    def summarize_read_only(self, correlation_id: str, briefing: str) -> str:
        ...


class ReadOnlyVoiceAdapter:
    def __init__(self, *, enabled: bool = False, transport: NovaSonicTransport | None = None) -> None:
        self._enabled = enabled
        self._transport = transport

    @property
    def status(self) -> VoiceStatus:
        if not self._enabled:
            return VoiceStatus.DISABLED
        return VoiceStatus.AVAILABLE if self._transport is not None else VoiceStatus.UNAVAILABLE

    def brief(self, correlation_id: str, briefing: str) -> VoiceBriefingResult:
        if not self._enabled:
            return VoiceBriefingResult(VoiceStatus.DISABLED, correlation_id, "Voice is disabled.")
        if self._transport is None:
            return VoiceBriefingResult(VoiceStatus.UNAVAILABLE, correlation_id, "Voice is unavailable.")
        try:
            summary = self._transport.summarize_read_only(correlation_id, briefing)
        except Exception:  # noqa: BLE001 - unavailable voice must not affect authorization.
            return VoiceBriefingResult(VoiceStatus.UNAVAILABLE, correlation_id, "Voice is unavailable.")
        return VoiceBriefingResult(VoiceStatus.AVAILABLE, correlation_id, summary)
