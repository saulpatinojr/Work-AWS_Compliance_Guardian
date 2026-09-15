# Continuous Compliance Guardian — Implementation Task List

**Status:** Planning only; tasks are not approved for execution until requirements and design receive human review.

**Ordering:** Complete in dependency order. Every task must preserve the Cedar-first boundary and the POC cost/safety constraints.

## Phase 0 — Review and capability gates

- [ ] **0.1 Approve requirements and design**
  - Review `requirements.md` and `design.md` with security, platform, and POC owners.
  - Resolve the design review questions and record decisions before implementation.
  - **Exit:** Requirements and design are marked approved; no code changes are part of this task.

- [ ] **0.2 Capture live AgentCore contract**
  - In a non-production sandbox, create or inspect the smallest representative Gateway/target definition needed to obtain the generated Cedar schema and exact action identifiers.
  - Verify Lambda target tool-schema limits, principal identity, target/resource representation, request input context, policy engine association, and policy analyzer behavior.
  - Verify the control-plane operation for policy updates, enforcement modes, propagation, IAM permissions, request IDs, and failure/rollback behavior.
  - **Exit:** A versioned, redacted capability record exists; all Cedar requirements map to real entity/action/context names; unresolved items block later policy work.

- [ ] **0.3 Capture Nova Sonic contract**
  - Verify model ID, region availability, quotas, bidirectional API, audio formats, browser transport, interruption events, and authentication path.
  - Decide whether the first implementation uses a real adapter or a mock while keeping voice disabled.
  - **Exit:** A capability record and explicit adapter boundary exist; no voice mutation path is permitted.

- [ ] **0.4 Resolve Terraform version baseline**
  - Compare the repository’s Terraform `>=1.8.0,<2.0.0` and AWS provider `~>5.0` constraints with the validated AgentCore resource schemas in AWS provider 6.64.0.
  - Select and pin a compatible runtime/provider pair, document the provider-upgrade risk, and plan lock-file changes.
  - **Exit:** Version decision is approved before Terraform resources are expanded.

## Phase 1 — Contracts, threat model, and policy model

- [ ] **1.1 Define typed contracts**
  - Define finding, discovery-run, remediation-request, tool input/output, decision-evidence, audit-event, policy-activation, and error contracts.
  - Include schema versions, correlation/request IDs, deterministic identities, redaction rules, idempotency keys, expected finding versions, and allowed status transitions.
  - **Exit:** Contracts are reviewable independently of implementation and cover every acceptance scenario.

- [ ] **1.2 Threat-model the trust boundaries**
  - Model admin, Cognito, API, discovery, AgentCore Gateway, Cedar, tool Lambdas, AWS sources, S3/DynamoDB, and Nova Sonic.
  - Identify confused-deputy, forged-tag/context, replay, privilege escalation, secret leakage, policy activation, and audit-integrity threats.
  - **Exit:** Mitigations map to requirements, IAM boundaries, tests, and operational alarms.

- [ ] **1.3 Reconcile Cedar policies with the live schema**
  - Convert current guardrail/permit intent into explicit per-tool policies using actual AgentCore action/resource/entity names.
  - Keep always-on forbids active; replace the broad wildcard permit with narrow action-specific permits.
  - Represent `CCGDemo=true` and `Environment=prod` using attributes that the caller cannot self-assert.
  - Define inactive/log-only permit behavior, activation version, rollback, concurrency, and policy analyzer gates.
  - **Exit:** Policies pass schema/analyzer validation and have no unreviewed wildcard authorization.

- [ ] **1.4 Define policy tests before policy deployment**
  - Specify allow, default-deny, forbid-overrides-permit, missing-tag, prod-tag, malformed-context, unknown-tool, inactive-permit, active-permit, stale-version, replay, and activation-failure tests.
  - **Exit:** Tests are executable against a double or validated sandbox boundary and cover CCG-REQ-008 through CCG-REQ-020.

## Phase 2 — Terraform foundation and security controls

- [ ] **2.1 Establish modular Terraform layout**
  - Create the reviewed `environments/poc` root and bounded modules without introducing application behavior.
  - Preserve Terraform Cloud as the only backend; add typed variables, outputs, default tags, and safe POC validation.
  - **Exit:** Format, initialization, backendless validation, and module contract checks pass without credentials or local state committed.

- [ ] **2.2 Harden evidence storage**
  - Refine private encrypted S3 audit storage, public-access blocking, ownership/policy controls, 30-day lifecycle, and the chosen versioning/immutability posture.
  - Refine on-demand DynamoDB current-finding/idempotency layout and seven-day CloudWatch log retention.
  - **Exit:** Storage controls are plan-visible, least privilege is reviewed, and retention tests exist.

- [ ] **2.3 Provision least-privilege identities**
  - Define separate discovery, control-plane, Gateway, tool, API, and audit-reader roles.
  - Scope permissions to the POC account, region, resource types, tags, and specific APIs; avoid wildcard administrative access.
  - **Exit:** IAM policy review and negative permission tests show discovery cannot mutate, console cannot bypass Gateway, and tools cannot activate policy.

- [ ] **2.4 Provision EventBridge and discovery runtime**
  - Add the configurable schedule with 15-minute default, Lambda runtime configuration, bounded timeout/concurrency, retries, and failure destination/metric where justified.
  - **Exit:** Schedule and runtime are deployable in the POC topology without NAT, always-on compute, or multi-AZ requirements.

- [ ] **2.5 Provision AgentCore Gateway and policy resources**
  - Add only the validated Gateway, target, Policy Engine, and policy resources using the approved provider version and actual schema.
  - Ensure inactive permit state and active forbids are represented without relying on application booleans.
  - **Exit:** Terraform plan shows the intended external policy boundary and no unreviewed mutation path.

## Phase 3 — Discovery and evidence path

- [ ] **3.1 Implement source adapters**
  - Add read-only adapters for Config, Security Hub, and CloudTrail behind interfaces/test doubles.
  - Define throttling, permission, malformed-response, and partial-run handling.
  - **Exit:** Unit tests cover source success/failure and no write permission is required.

- [ ] **3.2 Implement normalization and deduplication**
  - Produce deterministic finding IDs, evidence references, severity/status, target tags, timestamps, accepted-risk fields, and correlation propagation.
  - **Exit:** Replayed events update the same finding and cannot claim compliance from incomplete data.

- [ ] **3.3 Implement persistence and audit writes**
  - Upsert current state in DynamoDB and write redacted audit JSON to private S3.
  - Handle storage failure without silently losing decision/audit evidence.
  - **Exit:** Contract tests verify retention fields, redaction, idempotency, and partial failure behavior.

- [ ] **3.4 Replace the seed plan stub only after safety review**
  - Implement a reversible, explicitly sandbox-gated seed/cleanup workflow for 3–5 findings only after IAM and threat-model approval.
  - Ensure dry-run is real, `CCG_SANDBOX=true` and explicit confirmation are required, and cleanup is bounded.
  - **Exit:** Seed cannot target prod/out-of-scope resources and cleanup is tested before demo use.

## Phase 4 — Gateway tools and control plane

- [ ] **4.1 Implement four narrow remediation tools**
  - Build one bounded tool per approved operation with typed input validation, target allowlisting, safety-tag rechecks, least-privilege role, idempotency, and redacted outcomes.
  - **Exit:** Unit and integration tests cover allow, deny, no-op, failure, audit, and cleanup for each tool.

- [ ] **4.2 Implement Gateway invocation adapter**
  - Route remediation requests through the AgentCore Gateway MCP boundary only.
  - Capture exact action IDs, decision evidence, policy version, request IDs, and correlation IDs.
  - **Exit:** Direct tool/Lambda invocation is absent from agents, API, console, and voice paths.

- [ ] **4.3 Implement audited policy activation control plane**
  - Authenticate the admin, validate requested version/reason/concurrency, write intent, call the verified AgentCore control-plane update, reconcile effective state, and write result.
  - Fail closed on timeout, stale version, replay, schema error, or uncertain propagation.
  - **Exit:** Activation tests prove the UI cannot grant access and a failed/ambiguous update leaves mutations denied.

- [ ] **4.4 Implement remediation reconciliation**
  - Record requested/running/succeeded/no-op/failed/uncertain outcomes and require discovery confirmation before `RESOLVED`.
  - **Exit:** Findings, audit records, and tool outcomes remain consistent under retries and timeouts.

## Phase 5 — Console, identity, and optional voice

- [ ] **5.1 Implement Cognito/API control plane**
  - Add authenticated findings, policy-status, decision-evidence, activation, and remediation-request endpoints.
  - Enforce server-side input validation and correlation propagation; do not expose direct AWS mutation endpoints.
  - **Exit:** API authorization tests cover unauthenticated, unauthorized, stale, malformed, and valid requests.

- [ ] **5.2 Implement Next.js App Router console**
  - Display findings, evidence, effective policy version/mode, proposed actions, and server-confirmed outcomes.
  - Make remediation mode a server-state view, not a local authorizer.
  - **Exit:** Console acceptance scenarios ACC-01 through ACC-11 are demonstrable without a hidden bypass.

- [ ] **5.3 Implement Nova Sonic adapter or safe mock**
  - Add feature flag off by default, consent flow, read-only finding summary, correlation IDs, interruption handling, redaction, and unavailable fallback.
  - **Exit:** ACC-12 and ACC-13 pass; voice has no mutation tool visibility or Gateway bypass.

## Phase 6 — Validation, CI, demo, and operations

- [ ] **6.1 Build complete test matrix**
  - Run contract, policy, unit, integration, idempotency, audit, cleanup, and negative authorization tests.
  - Add a sandbox-only end-to-end path for discovery → deny → activation → allow/no-op → rediscovery.
  - **Exit:** Every requirement and acceptance scenario has traceable evidence.

- [ ] **6.2 Extend CI validation**
  - Add pinned Terraform fmt/validate/tflint and provider lock/schema checks; Ruff/pytest; TypeScript ESLint/typecheck; Cedar validation/analyzer checks; and secret scanning.
  - Keep real-cloud integration and remediation opt-in; never apply from CI.
  - **Exit:** Pull-request CI is validation-only and reports artifacts without secrets.

- [ ] **6.3 Add observability and budget checks**
  - Add structured JSON logs, correlation fields, metrics/alarms for discovery, denials, activation, tool failures, voice failures, and cleanup.
  - Add cost/resource guardrails and verify seven-day CloudWatch/30-day S3 retention.
  - **Exit:** Operational dashboard/runbook demonstrates the required evidence and budget posture.

- [ ] **6.4 Run the demo rehearsal**
  - Seed 3–5 sandbox-only findings; detect; show denied remediation with inactive permits; activate through the audited control plane; repeat the request; show allow/no-op; rediscover; show evidence; optionally run an interruptible voice briefing.
  - **Exit:** Demo evidence checklist is complete and all resources are attributable to the POC.

- [ ] **6.5 Document teardown and rollback**
  - Document permit deactivation, reconciliation, seed cleanup, reviewed Terraform destroy plan, resource deletion order, evidence retention, and incident handling.
  - **Exit:** Teardown is tested and no production or out-of-scope resource can be selected by default.

## Definition of done

The implementation may be considered complete only when:

- every approved EARS requirement has implementation and test evidence;
- every mutation traverses AgentCore Gateway/Cedar and no UI/application boolean authorizes it;
- forbids override permits, no-match denies, missing `CCGDemo` denies, and `Environment=prod` always denies;
- policy activation is versioned, audited, server-confirmed, concurrency-safe, and fail-closed;
- all four tools are narrow, idempotent, least-privilege, and cleanup-tested;
- discovery is read-only and later confirmation drives resolution;
- logs/audit records contain required correlation and decision evidence without secrets;
- the POC topology remains event-driven/serverless, under the budget target, with required retention;
- CI validates but does not apply; and
- the demo and teardown runbooks have been rehearsed in the dedicated sandbox.

## Explicitly not authorized by this task list

Approval of this list does not authorize live remediation, policy activation, production access, Terraform apply, destructive cleanup, credential creation, or adding dependencies/resources before the capability gates and human review are complete.
