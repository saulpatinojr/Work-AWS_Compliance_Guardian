"""Read-only discovery orchestration over typed source adapters."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from .contracts import AuditEvent, DiscoveryRun, DiscoverySignal, Finding, FindingStatus
from .ports import AuditSink, DiscoverySource, FindingRepository


def _finding_id(signal: DiscoverySignal) -> str:
    stable_key = f"{signal.rule_id}:{signal.target.arn}"
    return hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:32]


class DiscoveryCoordinator:
    """Collects signals and upserts current findings without mutation access."""

    def __init__(
        self,
        sources: Sequence[DiscoverySource],
        repository: FindingRepository,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._sources = tuple(sources)
        self._repository = repository
        self._audit_sink = audit_sink

    def run(self, correlation_id: str) -> DiscoveryRun:
        run_id = str(uuid4())
        started_at = datetime.now(timezone.utc)
        signals_seen = 0
        findings_upserted = 0
        failures: list[str] = []

        for source in self._sources:
            try:
                signals: Iterable[DiscoverySignal] = source.collect(correlation_id)
                for signal in signals:
                    if signal.correlation_id != correlation_id:
                        failures.append(f"{source.name}: correlation mismatch")
                        continue
                    signals_seen += 1
                    finding = Finding(
                        finding_id=_finding_id(signal),
                        rule_id=signal.rule_id,
                        source=signal.source,
                        target=signal.target,
                        severity=signal.severity,
                        title=signal.title,
                        evidence_refs=signal.evidence_refs,
                        status=FindingStatus.OPEN,
                        first_seen_at=signal.detected_at,
                        last_seen_at=signal.detected_at,
                        correlation_id=signal.correlation_id,
                    )
                    self._repository.upsert(finding)
                    findings_upserted += 1
            except Exception as exc:  # noqa: BLE001 - source isolation is intentional.
                failures.append(f"{source.name}: {type(exc).__name__}")

        completed_at = datetime.now(timezone.utc)
        result = DiscoveryRun(
            run_id=run_id,
            correlation_id=correlation_id,
            started_at=started_at,
            completed_at=completed_at,
            signals_seen=signals_seen,
            findings_upserted=findings_upserted,
            failures=tuple(failures),
        )
        if self._audit_sink is not None:
            self._audit_sink.record(
                AuditEvent(
                    event_id=str(uuid4()),
                    event_type="discovery.run",
                    actor="discovery-agent",
                    request_id=run_id,
                    correlation_id=correlation_id,
                    outcome="PARTIAL" if failures else "SUCCEEDED",
                    occurred_at=completed_at,
                    details={
                        "signals_seen": signals_seen,
                        "findings_upserted": findings_upserted,
                        "failure_count": len(failures),
                        "failures": list(failures),
                    },
                )
            )
        return result
