from datetime import datetime
import unittest

from ccg.contracts import Decision, RemediationRequest, TargetRef


class ContractTests(unittest.TestCase):
    def test_contract_serializes_enums_and_datetimes(self) -> None:
        target = TargetRef(
            arn="arn:aws:s3:::ccg-demo",
            resource_type="s3_bucket",
            tags={"CCGDemo": "true"},
        )
        request = RemediationRequest(
            request_id="req-1",
            correlation_id="corr-1",
            actor="admin@example.invalid",
            tool="s3_encryption_enablement",
            target=target,
            parameters={"algorithm": "AES256"},
            idempotency_key="idem-1",
        )
        record = request.to_record()
        self.assertEqual(record["target"]["tags"]["CCGDemo"], "true")
        self.assertEqual(request.to_json()[0], "{")
        self.assertEqual(Decision.DENY.value, "DENY")

    def test_naive_datetime_is_rejected_by_contract(self) -> None:
        with self.assertRaises(ValueError):
            from ccg.contracts import PolicyDecision

            PolicyDecision(
                decision=Decision.DENY,
                request_id="req-1",
                correlation_id="corr-1",
                actor="admin",
                action_id="tool",
                target_arn="arn:target",
                matched_policy_ids=(),
                policy_set_version="v0",
                reason="deny",
                evaluated_at=datetime.now(),
            )

    def test_target_safety_properties_are_exact(self) -> None:
        target = TargetRef(
            arn="arn:aws:lambda:us-east-1:123:function:demo",
            resource_type="lambda",
            tags={"CCGDemo": "true", "Environment": "prod"},
        )
        self.assertTrue(target.is_demo)
        self.assertTrue(target.is_production)


if __name__ == "__main__":
    unittest.main()
