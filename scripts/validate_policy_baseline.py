#!/usr/bin/env python3
"""Static safety checks for the Cedar intent files.

The live AgentCore analyzer remains mandatory once the Gateway schema exists.
This script only prevents the repository from reintroducing an obvious
wildcard permit or dropping the two global-open-ingress guardrails.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PERMITS = ROOT / "policies" / "remediation-permits.cedar"
GUARDRAILS = ROOT / "policies" / "guardrails.cedar"


def main() -> int:
    permits = PERMITS.read_text(encoding="utf-8")
    guardrails = GUARDRAILS.read_text(encoding="utf-8")
    if 'permit(principal, action, resource)' in permits:
        raise SystemExit("wildcard remediation permit is forbidden")
    for marker in ('"0.0.0.0/0"', '"::/0"'):
        if marker not in guardrails:
            raise SystemExit(f"missing global-open-ingress guardrail: {marker}")
    print("policy baseline static safety checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
