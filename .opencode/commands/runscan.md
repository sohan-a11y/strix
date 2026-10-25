---
description: Automated pentest of a target via the Strix MCP sandbox (account creation + testing + report, no API keys)
agent: pentest
---

Target: $1

Run the full autonomous pentest of this exact target per your system prompt:

1. `strix_sandbox_health` — if Docker/image problems, tell me the fix and stop.
2. Recon, then map surfaces, then register an account if the app requires one
   (use the browser tool; throwaway creds are fine).
3. Test what is in scope, carefully; confirm each finding with real captured
   evidence; `strix_report_finding` as you confirm things.
4. Close with `strix_finish_report` and give me: findings count by severity,
   the one-line descriptions, and the penetration_test_report.md path.

Stay strictly inside this target. If anything looks out of scope, stop and ask.
