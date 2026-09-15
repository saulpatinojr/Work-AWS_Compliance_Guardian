"""Typed, serializable contracts shared by CCG components.

These contracts deliberately contain no AWS SDK calls. Runtime adapters must
translate to and from these values at a trust boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import StrEnum
import json
from typing import Mapping, TypeAlias

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    REMEDIATION_REQUESTED = "REMEDIATION_REQUESTED"
    REMEDIATION_SUCCEEDED = "REMEDIATION_SUCCEEDED"
    REMEDIATION_NOOP = "REMEDIATION_NOOP"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolOutcome(StrEnum):
    APPLIED = "APPLIED"
    NOOP = "NOOP"
    FAILED = "FAILED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyEnforcementMode(StrEnum):
    LOG_ONLY = "LOG_ONLY"
    ACTIVE = "ACTIVE"


class ActivationOutcome(StrEnum):
    ACTIVATED = "ACTIVATED"
    DEACTIVATED = "DEACTIVATED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class VoiceStatus(StrEnum):
    DISABLED = "DISABLED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _jsonable(value: object) -> JsonValue:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if is_dataclass(value):
        return {field.name: _jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


class JsonContract:
    def to_record(self) -> dict[str, JsonValue]:
        record = _jsonable(self)
        if not isinstance(record, dict):
            raise TypeError("Contract did not serialize to an object")
        return record

    def to_json(self) -> str:
        return json.dumps(self.to_record(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class TargetRef(JsonContract):
    arn: str
    resource_type: str
    tags: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "arn", _require_text(self.arn, "arn"))
        object.__setattr__(self, "resource_type", _require_text(self.resource_type, "resource_type"))
        normalized = dict(self.tags)
        if any(not isinstance(key, str) or not key.strip() for key in normalized):
            raise ValueError("target tags must have non-empty string keys")
        if any(not isinstance(value, str) for value in normalized.values()):
            raise ValueError("target tag values must be strings")
        object.__setattr__(self, "tags", normalized)

    @property
    def is_demo(self) -> bool:
        return self.tags.get("CCGDemo") == "true"

    @property
    def is_production(self) -> bool:
        return self.tags.get("Environment", "").casefold() == "prod"


@dataclass(frozen=True, slots=True)
class RemediationRequest(JsonContract):
    request_id: str
    correlation_id: str
    actor: str
    tool: str
    target: TargetRef
    parameters: Mapping[str, JsonValue]
    idempotency_key: str
    expected_finding_version: int | None = None

    def __post_init__(self) -> None:
        for field_name in ("request_id", "correlation_id", "actor", "tool", "idempotency_key"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.expected_finding_version is not None and self.expected_finding_version < 0:
            raise ValueError("expected_finding_version must be non-negative")
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True, slots=True)
class RemediationCommand(JsonContract):
    """Untrusted API command; target identity is resolved server-side."""

    request_id: str
    correlation_id: str
    actor: str
    finding_id: str
    tool: str
    parameters: Mapping[str, JsonValue]
    idempotency_key: str
    expected_finding_version: int | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "request_id",
            "correlation_id",
            "actor",
            "finding_id",
            "tool",
            "idempotency_key",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.expected_finding_version is not None and self.expected_finding_version < 0:
            raise ValueError("expected_finding_version must be non-negative")
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True, slots=True)
class PolicyDecision(JsonContract):
    decision: Decision
    request_id: str
    correlation_id: str
    actor: str
    action_id: str
    target_arn: str
    matched_policy_ids: tuple[str, ...]
    policy_set_version: str
    reason: str
    evaluated_at: datetime

    def __post_init__(self) -> None:
        for field_name in (
            "request_id",
            "correlation_id",
            "actor",
            "action_id",
            "target_arn",
            "policy_set_version",
            "reason",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "evaluated_at", _require_aware(self.evaluated_at, "evaluated_at"))
        object.__setattr__(self, "matched_policy_ids", tuple(self.matched_policy_ids))


@dataclass(frozen=True, slots=True)
class ToolResult(JsonContract):
    outcome: ToolOutcome
    tool: str
    target_arn: str
    changed: bool
    message: str
    idempotency_replayed: bool = False
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("tool", "target_arn", "message"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "details", dict(self.details or {}))


@dataclass(frozen=True, slots=True)
class InvocationResult(JsonContract):
    decision: PolicyDecision
    tool_result: ToolResult | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent(JsonContract):
    event_id: str
    event_type: str
    actor: str
    request_id: str
    correlation_id: str
    outcome: str
    occurred_at: datetime
    details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        for field_name in ("event_id", "event_type", "actor", "request_id", "correlation_id", "outcome"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "occurred_at", _require_aware(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "details", dict(self.details))


@dataclass(frozen=True, slots=True)
class DiscoverySignal(JsonContract):
    signal_id: str
    rule_id: str
    source: str
    target: TargetRef
    severity: Severity
    title: str
    evidence_refs: tuple[str, ...]
    detected_at: datetime
    correlation_id: str
    attributes: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        for field_name in ("signal_id", "rule_id", "source", "title", "correlation_id"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "detected_at", _require_aware(self.detected_at, "detected_at"))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "attributes", dict(self.attributes))


@dataclass(frozen=True, slots=True)
class Finding(JsonContract):
    finding_id: str
    rule_id: str
    source: str
    target: TargetRef
    severity: Severity
    title: str
    evidence_refs: tuple[str, ...]
    status: FindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    correlation_id: str
    schema_version: str = "1"
    accepted_risk: Mapping[str, JsonValue] | None = None
    revision: int = 0

    def __post_init__(self) -> None:
        for field_name in ("finding_id", "rule_id", "source", "title", "correlation_id", "schema_version"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "first_seen_at", _require_aware(self.first_seen_at, "first_seen_at"))
        object.__setattr__(self, "last_seen_at", _require_aware(self.last_seen_at, "last_seen_at"))
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at cannot precede first_seen_at")
        if self.revision < 0:
            raise ValueError("revision must be non-negative")
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "accepted_risk", dict(self.accepted_risk or {}))


@dataclass(frozen=True, slots=True)
class DiscoveryRun(JsonContract):
    run_id: str
    correlation_id: str
    started_at: datetime
    completed_at: datetime
    signals_seen: int
    findings_upserted: int
    failures: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in ("run_id", "correlation_id"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "started_at", _require_aware(self.started_at, "started_at"))
        object.__setattr__(self, "completed_at", _require_aware(self.completed_at, "completed_at"))
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        if self.signals_seen < 0 or self.findings_upserted < 0:
            raise ValueError("discovery counts must be non-negative")
        object.__setattr__(self, "failures", tuple(self.failures))


@dataclass(frozen=True, slots=True)
class PolicyState(JsonContract):
    policy_engine_id: str
    policy_set_version: str
    enforcement_mode: PolicyEnforcementMode
    generation: int
    updated_by: str
    updated_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("policy_engine_id", "policy_set_version", "updated_by"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        object.__setattr__(self, "updated_at", _require_aware(self.updated_at, "updated_at"))


@dataclass(frozen=True, slots=True)
class PolicyActivationRequest(JsonContract):
    request_id: str
    correlation_id: str
    actor: str
    requested_version: str
    expected_generation: int
    reason: str
    activate: bool

    def __post_init__(self) -> None:
        for field_name in ("request_id", "correlation_id", "actor", "requested_version", "reason"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.expected_generation < 0:
            raise ValueError("expected_generation must be non-negative")


@dataclass(frozen=True, slots=True)
class PolicyActivationResult(JsonContract):
    outcome: ActivationOutcome
    request_id: str
    correlation_id: str
    state: PolicyState | None
    control_plane_request_id: str | None
    message: str

    def __post_init__(self) -> None:
        for field_name in ("request_id", "correlation_id", "message"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        if self.control_plane_request_id is not None:
            object.__setattr__(
                self,
                "control_plane_request_id",
                _require_text(self.control_plane_request_id, "control_plane_request_id"),
            )


@dataclass(frozen=True, slots=True)
class VoiceBriefingResult(JsonContract):
    status: VoiceStatus
    correlation_id: str
    summary: str
    interrupted: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "correlation_id", _require_text(self.correlation_id, "correlation_id"))
        object.__setattr__(self, "summary", _require_text(self.summary, "summary"))
