---
description: Authorized pentest using the Z4nzu/hackingtool catalog inside the Strix sandbox (no LLM key)
agent: Z4nzu
---

Target: $1
Scan mode: $2 (if empty, use `STRIX_MCP_SCAN_MODE`, default `deep`)

Run the full autonomous pentest of this exact target per your system prompt:

1. `strix_sandbox_health` — if Docker or the image is missing, tell me the
   exact fix and stop.
2. Restate the scope, read or derive the threat model, and make a short todo
   plan. Say which scan mode you are using.
3. Clone the hackingtool catalog into the sandbox (`/workspace/hackingtool`)
   and read its closed catalog plus the operator methodology. Choose only real
   tools from it — never invent a tool or command. Do not use hackingtool's own
   AI layer; you are the brain.
4. Recon and map the surface first. Prefer passive tools before active ones and
   stay inside the hard limits. Delegate to the `strix-*` specialists if the
   `task` tool is available, otherwise work inline.
5. Create your own throwaway accounts if auth is required, and a second one for
   access-control tests. Stay away from the excluded categories (DDOS, phishing,
   wireless capture, RATs, credential capture, mass targeting).
6. Confirm every finding with real captured proxy evidence, record coverage as
   you assess each surface, and call `strix_report_finding` while the exchange
   is fresh. Treat scanner output as a lead, not a finding.
7. Reconcile `needs_follow_up` coverage rows, optionally run the `strix-report`
   audit, then call `strix_finish_report` exactly once.

Give me at the end: findings by severity, a one-line description each, the
`penetration_test_report.md` path, and the honest coverage gaps.

Stay strictly inside this target. If anything looks out of scope, stop and ask.
