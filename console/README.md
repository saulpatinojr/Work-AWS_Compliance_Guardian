# CCG console

This Next.js App Router console is a static-exportable read/control surface. It calls an authenticated API configured with `NEXT_PUBLIC_API_BASE_URL` for findings, effective policy state, and policy activation requests.

The browser does not authorize mutations. Policy activation is server-side, versioned, audited, and delegated to the AgentCore control-plane adapter. Remediation requests must traverse the AgentCore Gateway Policy Engine. Nova Sonic is not exposed by this shell and remains disabled by default.

Install and validate with the pinned versions in `package.json`:

```powershell
npm install
npm run typecheck
npm run build
```
