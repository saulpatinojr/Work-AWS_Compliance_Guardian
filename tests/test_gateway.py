import unittest

from ccg.contracts import Decision, RemediationRequest, TargetRef, ToolOutcome, ToolResult
from ccg.testing import InMemoryCedarGateway, RecordingAuditSink


class GatewayBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = RecordingAuditSink()
        self.gateway = InMemoryCedarGateway(self.audit)
        self.calls = 0

        def tool(request: RemediationRequest) -> ToolResult:
            self.calls += 1
            return ToolResult(
                outcome=ToolOutcome.APPLIED,
                tool=request.tool,
                target_arn=request.target.arn,
                changed=True,
                message="sandbox change applied",
            )

        self.gateway.register("s3_encryption_enablement", tool)
        self.gateway.register("security_group_correction", tool)

    def request(
        self,
        *,
        tool: str = "s3_encryption_enablement",
        tags=None,
        parameters=None,
        key="idem-1",
    ) -> RemediationRequest:
        return RemediationRequest(
            request_id=f"req-{key}",
            correlation_id="corr-1",
            actor="admin",
            tool=tool,
            target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", tags or {"CCGDemo": "true"}),
            parameters=parameters or {},
            idempotency_key=key,
        )

    def test_inactive_permit_defaults_to_deny_before_tool(self) -> None:
        result = self.gateway.invoke(self.request())
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertEqual(result.decision.reason, "permit set is inactive")
        self.assertEqual(self.calls, 0)

    def test_missing_demo_tag_denies_even_when_permit_active(self) -> None:
        self.gateway.activate_permits("v1")
        result = self.gateway.invoke(self.request(tags={"Environment": "sandbox"}))
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertEqual(result.decision.reason, "CCGDemo=true is required")
        self.assertEqual(self.calls, 0)

    def test_production_tag_denies_even_when_permit_active(self) -> None:
        self.gateway.activate_permits("v1")
        result = self.gateway.invoke(self.request(tags={"CCGDemo": "true", "Environment": "prod"}))
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertEqual(result.decision.reason, "production target is forbidden")
        self.assertEqual(self.calls, 0)

    def test_forbid_overrides_active_permit(self) -> None:
        self.gateway.activate_permits("v1")
        result = self.gateway.invoke(
            self.request(
                tool="security_group_correction",
                parameters={"proposed_cidr": "0.0.0.0/0"},
            )
        )
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertEqual(result.decision.reason, "global-open ingress is forbidden")
        self.assertEqual(self.calls, 0)

    def test_allow_executes_registered_tool_and_records_audit(self) -> None:
        self.gateway.activate_permits("v1")
        result = self.gateway.invoke(self.request())
        self.assertEqual(result.decision.decision, Decision.ALLOW)
        self.assertEqual(result.tool_result.outcome, ToolOutcome.APPLIED)
        self.assertEqual(self.calls, 1)
        self.assertEqual(
            [event.event_type for event in self.audit.events],
            ["gateway.decision", "remediation.execution"],
        )

    def test_repeated_idempotency_key_does_not_execute_twice(self) -> None:
        self.gateway.activate_permits("v1")
        first = self.gateway.invoke(self.request())
        second = self.gateway.invoke(self.request(key="idem-1"))
        self.assertEqual(first.tool_result.outcome, ToolOutcome.APPLIED)
        self.assertTrue(second.tool_result.idempotency_replayed)
        self.assertEqual(self.calls, 1)

    def test_unknown_tool_is_denied(self) -> None:
        self.gateway.activate_permits("v1")
        result = self.gateway.invoke(self.request(tool="disable_cloudtrail"))
        self.assertEqual(result.decision.decision, Decision.DENY)
        self.assertEqual(result.decision.reason, "unregistered tool")
        self.assertEqual(self.calls, 0)


if __name__ == "__main__":
    unittest.main()
