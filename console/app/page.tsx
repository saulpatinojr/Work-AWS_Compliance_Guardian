"use client";

import { useEffect, useState } from "react";
import {
  Finding,
  getFindings,
  getPolicyState,
  PolicyState,
  requestPolicyActivation,
} from "../lib/api";

export default function HomePage() {
  const [policy, setPolicy] = useState<PolicyState | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reason, setReason] = useState("Approved sandbox demo activation");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      setError(null);
      const [nextPolicy, nextFindings] = await Promise.all([getPolicyState(), getFindings()]);
      setPolicy(nextPolicy);
      setFindings(nextFindings);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load compliance state");
    }
  }

  useEffect(() => {
    const refreshTimer = window.setTimeout(() => {
      void refresh();
    }, 0);
    return () => window.clearTimeout(refreshTimer);
  }, []);

  async function activate() {
    if (!policy) return;
    try {
      setBusy(true);
      setError(null);
      await requestPolicyActivation({
        requestedVersion: policy.enforcement_mode === "ACTIVE" ? policy.policy_set_version : "v1",
        expectedGeneration: policy.generation,
        reason,
        activate: policy.enforcement_mode !== "ACTIVE",
      });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy activation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <header>
        <div>
          <h1>Continuous Compliance Guardian</h1>
          <p>Dedicated sandbox findings and Cedar-governed remediation evidence.</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={busy}>Refresh</button>
      </header>

      {error && <p className="error" role="alert">{error}</p>}

      <section aria-labelledby="policy-heading">
        <h2 id="policy-heading">Effective policy state</h2>
        <div className="grid">
          <div className="card"><strong>Mode</strong><p className="status">{policy?.enforcement_mode ?? "Loading"}</p></div>
          <div className="card"><strong>Policy set</strong><p><code>{policy?.policy_set_version ?? "Loading"}</code></p></div>
          <div className="card"><strong>Generation</strong><p>{policy?.generation ?? "Loading"}</p></div>
          <div className="card"><strong>Updated by</strong><p>{policy?.updated_by ?? "Loading"}</p></div>
        </div>
        <p>Changing this control submits a versioned server request. The browser never authorizes a remediation; mutations must still pass the AgentCore Gateway Policy Engine.</p>
        <label>
          Activation reason
          <input value={reason} onChange={(event) => setReason(event.target.value)} disabled={busy} />
        </label>{" "}
        <button type="button" onClick={() => void activate()} disabled={!policy || busy}>
          {policy?.enforcement_mode === "ACTIVE" ? "Deactivate permits" : "Activate permits"}
        </button>
      </section>

      <section aria-labelledby="findings-heading">
        <h2 id="findings-heading">Current findings</h2>
        {findings.length === 0 ? <p>No findings returned.</p> : findings.map((finding) => (
          <article className="card" key={finding.finding_id}>
            <h3>{finding.title}</h3>
            <p>{finding.severity} · {finding.status} · <code>{finding.target_arn}</code></p>
          </article>
        ))}
      </section>

      <section>
        <h2>Authorization boundary</h2>
        <p>Remediation requests are sent to the authenticated API and delegated to the AgentCore Gateway. This console has no direct AWS mutation client and voice is disabled by default.</p>
      </section>
    </main>
  );
}
