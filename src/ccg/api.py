"""Framework-neutral API service boundary for console and Lambda adapters."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import (
    InvocationResult,
    PolicyActivationRequest,
    PolicyActivationResult,
    PolicyState,
    RemediationCommand,
    RemediationRequest,
)
from .policy import PolicyActivationService
from .ports import FindingTargetResolver, GatewayInvocationPort


class UnauthorizedError(PermissionError):
    """The caller was not authenticated or lacked the admin control role."""


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    actor: str
    roles: frozenset[str]
    authenticated: bool = True

    def __post_init__(self) -> None:
        if not self.actor.strip():
            raise ValueError("actor must be non-empty")


class ComplianceApi:
    """API service with no direct AWS mutation capability.

    Remediation requests are delegated to the AgentCore Gateway port. This
    service never evaluates a local permit or UI flag to authorize a mutation.
    """

    def __init__(
        self,
        gateway: GatewayInvocationPort,
        policy: PolicyActivationService,
        findings: FindingTargetResolver,
    ) -> None:
        self._gateway = gateway
        self._policy = policy
        self._findings = findings

    def get_policy_state(self, principal: AuthenticatedPrincipal) -> PolicyState:
        self._require_authenticated(principal)
        return self._policy.current_state()

    def get_findings(self, principal: AuthenticatedPrincipal):
        self._require_authenticated(principal)
        return self._findings.list_findings()

    def request_remediation(
        self,
        principal: AuthenticatedPrincipal,
        command: RemediationCommand,
    ) -> InvocationResult:
        self._require_authenticated(principal)
        if "CCGAdmin" not in principal.roles and "CCGRemediator" not in principal.roles:
            raise UnauthorizedError("CCGRemediator role is required for remediation requests")
        if principal.actor != command.actor:
            raise UnauthorizedError("request actor does not match authenticated principal")
        if command.expected_finding_version is None:
            raise ValueError("expected finding version is required")
        finding = self._findings.resolve_finding(command.finding_id)
        if finding is None:
            raise ValueError("finding target could not be resolved")
        if command.expected_finding_version != finding.revision:
            raise ValueError("finding version is stale")
        request = RemediationRequest(
            request_id=command.request_id,
            correlation_id=command.correlation_id,
            actor=command.actor,
            tool=command.tool,
            target=finding.target,
            parameters=command.parameters,
            idempotency_key=command.idempotency_key,
            expected_finding_version=command.expected_finding_version,
        )
        return self._gateway.invoke(request)

    def change_policy_state(
        self,
        principal: AuthenticatedPrincipal,
        request: PolicyActivationRequest,
    ) -> PolicyActivationResult:
        self._require_authenticated(principal)
        if "CCGAdmin" not in principal.roles:
            raise UnauthorizedError("CCGAdmin role is required for policy activation")
        if principal.actor != request.actor:
            raise UnauthorizedError("request actor does not match authenticated principal")
        return self._policy.apply(request)

    @staticmethod
    def _require_authenticated(principal: AuthenticatedPrincipal) -> None:
        if not principal.authenticated:
            raise UnauthorizedError("authentication is required")
