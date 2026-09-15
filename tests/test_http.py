import json
import unittest

from ccg.api import AuthenticatedPrincipal, ComplianceApi
from ccg.http import ApiHttpAdapter
from ccg.policy import InMemoryPolicyControlPlane, PolicyActivationService
from ccg.testing import InMemoryCedarGateway, InMemoryFindingRepository, RecordingAuditSink


class HttpAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        audit = RecordingAuditSink()
        self.gateway = InMemoryCedarGateway(audit)
        policy = PolicyActivationService(InMemoryPolicyControlPlane(), audit)
        self.adapter = ApiHttpAdapter(
            ComplianceApi(self.gateway, policy, InMemoryFindingRepository()),
            lambda event: AuthenticatedPrincipal("admin", frozenset({"CCGAdmin"})),
        )

    def test_policy_read_returns_json(self) -> None:
        response = self.adapter.handle({"httpMethod": "GET", "path": "/policy"})
        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["enforcement_mode"], "LOG_ONLY")

    def test_malformed_remediation_is_client_error(self) -> None:
        response = self.adapter.handle(
            {
                "httpMethod": "POST",
                "path": "/remediation",
                "headers": {"x-correlation-id": "corr-1"},
                "body": json.dumps({"tool": "unknown"}),
            }
        )
        self.assertEqual(response["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
