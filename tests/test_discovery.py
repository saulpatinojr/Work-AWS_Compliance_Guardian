from datetime import datetime, timezone
import unittest

from ccg.contracts import DiscoverySignal, Severity, TargetRef
from ccg.discovery import DiscoveryCoordinator
from ccg.testing import FailingDiscoverySource, InMemoryFindingRepository, StaticDiscoverySource


class DiscoveryTests(unittest.TestCase):
    def test_discovery_normalizes_deterministically_and_isolates_source_failure(self) -> None:
        detected_at = datetime.now(timezone.utc)
        signal = DiscoverySignal(
            signal_id="signal-1",
            rule_id="s3-encryption",
            source="config",
            target=TargetRef("arn:aws:s3:::ccg-demo", "s3_bucket", {"CCGDemo": "true"}),
            severity=Severity.HIGH,
            title="Bucket encryption is missing",
            evidence_refs=("config:signal-1",),
            detected_at=detected_at,
            correlation_id="corr-1",
            attributes={"expected_algorithm": "AES256"},
        )
        repository = InMemoryFindingRepository()
        coordinator = DiscoveryCoordinator(
            [
                StaticDiscoverySource("config", [signal]),
                FailingDiscoverySource("securityhub"),
            ],
            repository,
        )
        run = coordinator.run("corr-1")
        self.assertEqual(run.signals_seen, 1)
        self.assertEqual(run.findings_upserted, 1)
        self.assertEqual(run.failures, ("securityhub: RuntimeError",))
        finding = next(iter(repository.findings.values()))
        self.assertEqual(finding.rule_id, "s3-encryption")
        self.assertEqual(finding.status.value, "OPEN")

        second_repository = InMemoryFindingRepository()
        second_run = DiscoveryCoordinator([StaticDiscoverySource("config", [signal])], second_repository).run("corr-1")
        self.assertEqual(tuple(repository.findings)[0], tuple(second_repository.findings)[0])
        self.assertEqual(second_run.failures, ())


if __name__ == "__main__":
    unittest.main()
