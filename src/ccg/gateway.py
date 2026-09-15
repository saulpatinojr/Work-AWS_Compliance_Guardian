"""Production-facing AgentCore Gateway adapter boundary."""

from __future__ import annotations

from typing import Protocol

from .contracts import InvocationResult, RemediationRequest
from .ports import GatewayInvocationPort


class AgentCoreGatewayTransport(Protocol):
    """Narrow transport seam for the AWS AgentCore Gateway client.

    The implementation will call the validated AgentCore Gateway MCP endpoint.
    Authorization belongs to the remote Gateway Policy Engine, not this class.
    """

    def invoke(self, request: RemediationRequest) -> InvocationResult:
        ...


class AgentCoreGatewayClient(GatewayInvocationPort):
    """Delegates mutation requests to AgentCore without local authorization."""

    def __init__(self, transport: AgentCoreGatewayTransport) -> None:
        self._transport = transport

    def invoke(self, request: RemediationRequest) -> InvocationResult:
        return self._transport.invoke(request)
