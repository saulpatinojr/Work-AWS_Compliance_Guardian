"""Audited AgentCore policy activation boundary.

This module does not decide whether a remediation is allowed. Remediation
authorization remains the responsibility of the remote AgentCore Gateway
Policy Engine. The control-plane transport only changes the separately
versioned policy enforcement state after the admin control-plane request is
validated and audited.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from .contracts import (
    ActivationOutcome,
    AuditEvent,
    PolicyActivationRequest,
    PolicyActivationResult,
    PolicyEnforcementMode,
    PolicyState,
)
from .ports import AuditSink


class PolicyControlPlaneTransport(Protocol):
    def get_state(self) -> PolicyState:
        ...

    def force_deny_safe(self) -> PolicyState:
        """Reconcile the remote policy engine to a non-authorizing mode."""
        ...


class PolicyActivationService:
    """Performs versioned, audited policy state changes through a control plane."""

    def __init__(
        self,
        transport: PolicyControlPlaneTransport,
        audit_sink: AuditSink,
        approved_versions: frozenset[str] | None = None,
    ) -> None:
        self._transport = transport
        self._audit_sink = audit_sink
        self._approved_versions = approved_versions or frozenset({"permits-inactive", "v1"})
        self._processed_requests: dict[str, PolicyActivationResult] = {}

    def current_state(self) -> PolicyState:
        return self._transport.get_state()

    def apply(self, request: PolicyActivationRequest) -> PolicyActivationResult:
        if request.request_id in self._processed_requests:
            return self._processed_requests[request.request_id]
        current = self._transport.get_state()
        if request.requested_version not in self._approved_versions:
            return self._reject(request, current, "policy version is not approved")
        if not request.activate and request.requested_version != current.policy_set_version:
            return self._reject(request, current, "deactivation version does not match effective version")
        if request.expected_generation != current.generation:
            return self._reject(request, current, "stale policy generation")

        desired_mode = PolicyEnforcementMode.ACTIVE if request.activate else PolicyEnforcementMode.LOG_ONLY
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.intent",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome="REQUESTED",
                occurred_at=datetime.now(timezone.utc),
                details={
                    "requested_version": request.requested_version,
                    "expected_generation": request.expected_generation,
                    "desired_mode": desired_mode,
                    "reason": request.reason,
                },
            )
        )

        try:
            state, control_plane_request_id = self._transport.update_policy_set(request, desired_mode)
        except Exception:  # noqa: BLE001 - reconcile or fail closed at the control-plane boundary.
            try:
                reconciled = self._transport.force_deny_safe()
                message = "policy update failed; remote policy reconciled to deny-safe mode"
            except Exception:  # noqa: BLE001 - manual reconciliation is required if rollback fails.
                reconciled = None
                message = "policy update state is unknown; mutations must remain blocked pending reconciliation"
            self._audit_sink.record(
                AuditEvent(
                    event_id=str(uuid4()),
                    event_type="policy.activation.result",
                    actor=request.actor,
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                    outcome=ActivationOutcome.FAILED.value,
                    occurred_at=datetime.now(timezone.utc),
                    details={
                        "desired_mode": desired_mode,
                        "effective_state": "DENY_SAFE" if reconciled is not None else "UNKNOWN",
                    },
                )
            )
            result = PolicyActivationResult(
                outcome=ActivationOutcome.FAILED,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                state=reconciled,
                control_plane_request_id=None,
                message=message,
            )
            self._processed_requests[request.request_id] = result
            return result

        outcome = ActivationOutcome.ACTIVATED if request.activate else ActivationOutcome.DEACTIVATED
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.result",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=outcome.value,
                occurred_at=datetime.now(timezone.utc),
                details={
                    "effective_version": state.policy_set_version,
                    "effective_mode": state.enforcement_mode,
                    "generation": state.generation,
                    "control_plane_request_id": control_plane_request_id,
                },
            )
        )
        result = PolicyActivationResult(
            outcome=outcome,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            state=state,
            control_plane_request_id=control_plane_request_id,
            message="policy state updated through the AgentCore control plane",
        )
        self._processed_requests[request.request_id] = result
        return result

    def _reject(self, request: PolicyActivationRequest, current: PolicyState, reason: str) -> PolicyActivationResult:
        self._audit_sink.record(
            AuditEvent(
                event_id=str(uuid4()),
                event_type="policy.activation.result",
                actor=request.actor,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                outcome=ActivationOutcome.REJECTED.value,
                occurred_at=datetime.now(timezone.utc),
                details={
                    "reason": reason,
                    "requested_version": request.requested_version,
                    "current_version": current.policy_set_version,
                    "current_generation": current.generation,
                },
            )
        )
        result = PolicyActivationResult(
            outcome=ActivationOutcome.REJECTED,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            state=current,
            control_plane_request_id=None,
            message=reason,
        )
        self._processed_requests[request.request_id] = result
        return result


class InMemoryPolicyControlPlane(PolicyControlPlaneTransport):
    """Test double; never use this as production policy enforcement."""

    def __init__(self, policy_engine_id: str = "test-engine") -> None:
        self._state = PolicyState(
            policy_engine_id=policy_engine_id,
            policy_set_version="permits-inactive",
            enforcement_mode=PolicyEnforcementMode.LOG_ONLY,
            generation=0,
            updated_by="system",
            updated_at=datetime.now(timezone.utc),
        )
        self.fail_next = False
        self._request_ids: set[str] = set()

    def get_state(self) -> PolicyState:
        return self._state

    def update_policy_set(
        self,
        request: PolicyActivationRequest,
        enforcement_mode: PolicyEnforcementMode,
    ) -> tuple[PolicyState, str]:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated control-plane failure")
        if request.request_id in self._request_ids:
            raise RuntimeError("replayed control-plane request")
        if request.expected_generation != self._state.generation:
            raise RuntimeError("stale control-plane generation")
        self._request_ids.add(request.request_id)
        self._state = PolicyState(
            policy_engine_id=self._state.policy_engine_id,
            policy_set_version=request.requested_version,
            enforcement_mode=enforcement_mode,
            generation=self._state.generation + 1,
            updated_by=request.actor,
            updated_at=datetime.now(timezone.utc),
        )
        return self._state, f"cp-{uuid4()}"

    def force_deny_safe(self) -> PolicyState:
        if self._state.enforcement_mode is PolicyEnforcementMode.LOG_ONLY:
            return self._state
        request = PolicyActivationRequest(
            request_id=f"rollback-{uuid4()}",
            correlation_id=f"rollback-{uuid4()}",
            actor="system-reconciliation",
            requested_version=self._state.policy_set_version,
            expected_generation=self._state.generation,
            reason="automatic deny-safe reconciliation",
            activate=False,
        )
        state, _ = self.update_policy_set(request, PolicyEnforcementMode.LOG_ONLY)
        return state
