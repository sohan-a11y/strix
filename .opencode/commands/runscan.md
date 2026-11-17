---
description: Automated pentest of a target via the Strix MCP sandbox (account creation + testing + report, no API keys)
agent: pentest
---

Target: $1
Scan mode: $2 (if empty, use `STRIX_MCP_SCAN_MODE`, default `deep`)

Run the full autonomous pentest of this exact target per your system prompt:

1. `strix_sandbox_health` — if Docker or the image is missing, tell me the
   exact fix and stop.
2. Restate the scope in one line, then read or derive the threat model
   (`strix_threat_model_get` / `threat_model_save`), then create a short todo
   plan.
3. Recon and surface mapping first. If the specialist subagents are
   available, delegate recon to `strix-recon` and hand its surface list to
   `strix-web` / `strix-api`; otherwise do it inline.
4. Register your own throwaway account if the app requires auth, and a second
   one when access-control testing needs it.
5. Test what is in scope, carefully. Confirm every finding with real captured
   evidence (proxy exchange ids), record coverage as you go, and
   `strix_report_finding` while the context is fresh.
6. Reconcile `needs_follow_up` coverage rows, optionally run `strix-report`
   over the findings, then close with `strix_finish_report`.

Give me at the end: findings count by severity, a one-line description each,
the `penetration_test_report.md` path, and the honest coverage gaps.

Stay strictly inside this target. If anything looks out of scope, stop and ask.
