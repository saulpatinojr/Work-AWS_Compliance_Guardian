from datetime import datetime, timezone
import unittest

from ccg.contracts import DiscoverySignal, Severity, TargetRef
from ccg.discovery import DiscoveryCoordinator
from ccg.testing import InMemoryFindingRepository, RecordingAuditSink, StaticDiscoverySource


class DiscoveryAuditTests(unittest.TestCase):
    def test_discovery_run_emits_structured_audit_event(self) -> None:
        signal = DiscoverySignal(
            signal_id="signal-1",
            rule_id="s3-encryption",
            source="config",
            target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
            severity=Severity.HIGH,
            title="Encryption missing",
            evidence_refs=("config:signal-1",),
            detected_at=datetime.now(timezone.utc),
            correlation_id="corr-1",
            attributes={},
        )
        audit = RecordingAuditSink()
        run = DiscoveryCoordinator(
            [StaticDiscoverySource("config", [signal])],
            InMemoryFindingRepository(),
            audit,
        ).run("corr-1")
        self.assertEqual(run.findings_upserted, 1)
        self.assertEqual(audit.events[0].event_type, "discovery.run")
        self.assertEqual(audit.events[0].outcome, "SUCCEEDED")


if __name__ == "__main__":
    unittest.main()
