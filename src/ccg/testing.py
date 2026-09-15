"""Test doubles for contract and authorization-boundary tests.

`InMemoryCedarGateway` is intentionally not a production authorizer. It models
only the safety semantics required to test callers until a live AgentCore
Gateway schema and policy engine are available.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from .contracts import (
    AuditEvent,
    Decision,
    Finding,
    InvocationResult,
    PolicyDecision,
    RemediationRequest,
    TargetRef,
    ToolOutcome,
    ToolResult,
)
from .ports import AuditSink, DiscoverySource, FindingRepository, GatewayInvocationPort

ToolHandler = Callable[[RemediationRequest], ToolResult]


class RecordingAuditSink(AuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class InMemoryFindingRepository(FindingRepository):
    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}

    def upsert(self, finding: Finding) -> None:
        self.findings[finding.finding_id] = finding

    def resolve_finding(self, finding_id: str) -> Finding | None:
        return self.findings.get(finding_id)

    def resolve_target(self, finding_id: str) -> TargetRef | None:
        finding = self.resolve_finding(finding_id)
        return finding.target if finding is not None else None

    def list_findings(self) -> list[Finding]:
        return list(self.findings.values())


class StaticDiscoverySource(DiscoverySource):
    def __init__(self, name: str, signals: Iterable) -> None:
        self.name = name
        self._signals = tuple(signals)

    def collect(self, correlation_id: str):
        return self._signals


class FailingDiscoverySource(DiscoverySource):
    def __init__(self, name: str, error: Exception | None = None) -> None:
        self.name = name
        self._error = error or RuntimeError("source unavailable")

    def collect(self, correlation_id: str):
        raise self._error


class InMemoryCedarGateway(GatewayInvocationPort):
    """Minimal test-only model of the external Gateway/Cedar boundary."""

    def __init__(self, audit_sink: AuditSink, *, permit_active: bool = False) -> None:
        self._audit_sink = audit_sink
        self._permit_active = permit_active
        self._policy_version = "permits-inactive"
        self._tools: dict[str, ToolHandler] = {}
        self._replays: dict[str, ToolResult] = {}

    def register(self, tool: str, handler: ToolHandler) -> None:
        self._tools[tool] = handler

    def activate_permits(self, version: str) -> None:
        self._permit_active = True
        self._policy_version = version

    def invoke(self, request: RemediationRequest) -> InvocationResult:
        decision = self._evaluate(request)
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="gateway.decision",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=decision.decision.value,
                occurred_at=decision.evaluated_at,
                details={
                    "action_id": request.tool,
                    "target_arn": request.target.arn,
                    "matched_policy_ids": list(decision.matched_policy_ids),
                    "policy_set_version": decision.policy_set_version,
                    "reason": decision.reason,
                },
            )
        )
        if decision.decision is Decision.DENY:
            return InvocationResult(decision=decision)

        if request.idempotency_key in self._replays:
            replay = replace(self._replays[request.idempotency_key], idempotency_replayed=True)
            return InvocationResult(decision=decision, tool_result=replay)

        try:
            result = self._tools[request.tool](request)
        except Exception:  # noqa: BLE001 - boundary converts tool failures to typed outcomes.
            result = ToolResult(
                outcome=ToolOutcome.FAILED,
                tool=request.tool,
                target_arn=request.target.arn,
                changed=False,
                message="tool execution failed",
                details={"error_type": "tool_failure"},
            )
        self._replays[request.idempotency_key] = result
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="remediation.execution",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=result.outcome.value,
                occurred_at=datetime.now(timezone.utc),
                details={
                    "tool": result.tool,
                    "target_arn": result.target_arn,
                    "changed": result.changed,
                    "idempotency_replayed": result.idempotency_replayed,
                },
            )
        )
        return InvocationResult(decision=decision, tool_result=result)

    def _evaluate(self, request: RemediationRequest) -> PolicyDecision:
        now = datetime.now(timezone.utc)
        matched: tuple[str, ...] = ()
        reason = "default deny"

        if request.tool not in self._tools:
            reason = "unregistered tool"
            matched = ("always-deny-unregistered-tool",)
        elif request.target.is_production:
            reason = "production target is forbidden"
            matched = ("always-deny-production-target",)
        elif not request.target.is_demo:
            reason = "CCGDemo=true is required"
            matched = ("always-deny-missing-demo-tag",)
        elif (
            request.tool == "security_group_correction"
            and request.parameters.get("proposed_cidr") in {"0.0.0.0/0", "::/0"}
        ):
            reason = "global-open ingress is forbidden"
            matched = ("always-deny-global-open-ingress",)
        elif request.tool == "s3_encryption_enablement" and request.parameters.get("make_public") is True:
            reason = "public S3 changes are forbidden"
            matched = ("always-deny-public-s3",)
        elif request.tool == "disable_cloudtrail":
            reason = "CloudTrail disablement is forbidden"
            matched = ("always-deny-cloudtrail-disablement",)
        elif not self._permit_active:
            reason = "permit set is inactive"
            matched = ("default-deny-permits-inactive",)
        else:
            reason = "registered action permit matched"
            matched = (f"permit-{request.tool}",)

        decision = (
            Decision.ALLOW
            if self._permit_active
            and not reason.endswith("forbidden")
            and reason == "registered action permit matched"
            else Decision.DENY
        )
        return PolicyDecision(
            decision=decision,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            actor=request.actor,
            action_id=request.tool,
            target_arn=request.target.arn,
            matched_policy_ids=matched,
            policy_set_version=self._policy_version,
            reason=reason,
            evaluated_at=now,
        )
