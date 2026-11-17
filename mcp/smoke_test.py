"""Parity check for the Strix MCP server.

Spawns ``mcp/server.py`` over stdio exactly as a coding agent does and
exercises the whole deterministic surface: tool inventory, skills, notes,
coverage, threat model, todos, the finding lifecycle, the canonical artifacts
and the final report. LLM keys are removed from the child environment, so a
pass is proof that none are needed.

    .venv/Scripts/python.exe mcp/smoke_test.py
    .venv/Scripts/python.exe mcp/smoke_test.py --with-sandbox

The first form touches no Docker. ``--with-sandbox`` additionally boots the
Kali container and runs ``sandbox_health`` + one ``sandbox_exec`` (needs Docker
and the sandbox image pulled).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp.client.stdio import stdio_client

from mcp import ClientSession, StdioServerParameters


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TOOLS = {
    "browser",
    "coverage_list",
    "coverage_record",
    "coverage_update",
    "finish_report",
    "note_create",
    "note_delete",
    "note_get",
    "note_list",
    "note_update",
    "proxy_list_requests",
    "proxy_list_sitemap",
    "proxy_repeat_request",
    "proxy_scope_rules",
    "proxy_view_request",
    "proxy_view_sitemap_entry",
    "report_delete",
    "report_finding",
    "report_get",
    "report_list",
    "report_update",
    "sandbox_exec",
    "sandbox_health",
    "sandbox_read_file",
    "sandbox_stop",
    "sandbox_write_file",
    "skill_list",
    "skill_load",
    "threat_model_amend",
    "threat_model_get",
    "threat_model_save",
    "todo_create",
    "todo_delete",
    "todo_list",
    "todo_mark_done",
    "todo_mark_pending",
    "todo_update",
}

THREAT_MODEL = """# Threat Model: app.example.test

## Overview
A React single-page dashboard talking to a REST API. Registered users hold
bearer tokens; an admin role exists for support staff. The public surface is
the marketing site plus the authenticated API.

## Trust Boundaries and Assumptions
- Browser to API: the attacker controls every header, body and query value.
- Tenant boundary: one account must never read another account's records.
- Admin boundary: role claims come from the server, never from the client.

## Attack Surface and Attacker Stories
- Object reads and writes keyed by sequential ids (IDOR/BOLA, one hop).
- Profile fields rendered back to other users (stored XSS).
- Checkout endpoints that accept client-supplied amounts or credits.

## Severity Calibration
Critical: cross-tenant read/write at scale or auth bypass. High: privilege
escalation within a tenant, SQLi. Medium: stored XSS reaching another user.
Low: verbose errors and missing hardening headers with a demonstrated path.
"""

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"[PASS] {label}", flush=True)
        return
    FAILURES.append(label)
    print(f"[FAIL] {label}" + (f" :: {detail}" if detail else ""), flush=True)


def _venv_python() -> str:
    for candidate in (
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ):
        if candidate.exists():
            return str(candidate)
    sys.exit("[!] run inside the repo (needs .venv)")


async def call(session: ClientSession, name: str, args: dict[str, Any] | None = None) -> Any:
    result = await session.call_tool(name, args or {})
    text = result.content[0].text if result.content else ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


async def run(session: ClientSession, run_root: Path, with_sandbox: bool) -> None:
    # --- inventory ---------------------------------------------------------
    init = await session.initialize()
    check("server identifies itself", bool(init.serverInfo.name), init.serverInfo.name)

    tools = await session.list_tools()
    names = {t.name for t in tools.tools}
    check(
        "tool surface is the full 37-tool set",
        names == EXPECTED_TOOLS,
        f"missing={sorted(EXPECTED_TOOLS - names)} unexpected={sorted(names - EXPECTED_TOOLS)}",
    )

    # --- skills ------------------------------------------------------------
    skills = await call(session, "skill_list")
    check("skill_list returns 65 public packs", skills.get("count") == 65, str(skills)[:160])
    body = await call(session, "skill_load", {"skills": ["xss"]})
    check("skill_load returns markdown", isinstance(body, str) and len(body) > 500, str(body)[:120])
    missing = await call(session, "skill_load", {"skills": ["not_a_real_skill"]})
    check("unknown skill is reported, not silently ignored", "not_a_real_skill" in str(missing))

    # --- notes -------------------------------------------------------------
    note = await call(
        session,
        "note_create",
        {"title": "smoke note", "content": "hello from parity", "tags": ["smoke"]},
    )
    check("note_create", note.get("success") is True, str(note)[:160])
    note_id = note.get("note_id", "")
    listing = await call(session, "note_list")
    check("note_list sees the note", str(listing.get("total_count")) == "1", str(listing)[:160])
    check(
        "note_get returns content",
        "hello from parity" in str(await call(session, "note_get", {"note_id": note_id})),
    )
    check(
        "note_update",
        (await call(session, "note_update", {"note_id": note_id, "title": "smoke note v2"})).get(
            "success"
        )
        is True,
    )

    # --- coverage ----------------------------------------------------------
    cov = await call(
        session,
        "coverage_record",
        {
            "surface": "api.example.test /login",
            "risk_area": "sqli",
            "outcome": "no_issue_found",
            "evidence": "parameterized query observed",
        },
    )
    check("coverage_record", cov.get("success") is True, str(cov)[:160])
    entry_id = cov.get("entry_id", "")
    need = await call(
        session,
        "coverage_record",
        {
            "surface": "api.example.test /x",
            "risk_area": "idor",
            "outcome": "ruled_out",
            "evidence": "",
        },
    )
    check(
        "ruled_out without evidence is rejected", need.get("success") is not True, str(need)[:160]
    )
    check(
        "coverage_update",
        (
            await call(
                session,
                "coverage_update",
                {"entry_id": entry_id, "outcome": "reported", "evidence": "finding vuln-0001"},
            )
        ).get("success")
        is True,
    )
    rows = await call(session, "coverage_list")
    check("coverage_list", "api.example.test" in str(rows), str(rows)[:160])
    await call(
        session,
        "coverage_record",
        {
            "surface": "api.example.test /search",
            "risk_area": "sqli",
            "outcome": "no_issue_found",
            "evidence": "prepared statements, no string concat",
        },
    )

    # --- threat model ------------------------------------------------------
    absent = await call(session, "threat_model_get", {"target": "https://app.example.test"})
    check(
        "threat_model_get reports absence before save",
        absent.get("found") is False,
        str(absent)[:160],
    )
    check(
        "thin threat model is rejected",
        (
            await call(
                session,
                "threat_model_save",
                {"target": "https://app.example.test", "content": "# x\n- y"},
            )
        ).get("success")
        is not True,
    )
    saved = await call(
        session,
        "threat_model_save",
        {"target": "https://app.example.test", "content": THREAT_MODEL},
    )
    check("threat_model_save", saved.get("success") is True, str(saved)[:160])
    check(
        "threat_model_get after save",
        "Tenant boundary"
        in str(await call(session, "threat_model_get", {"target": "https://app.example.test"})),
    )
    amended = await call(
        session,
        "threat_model_amend",
        {
            "target": "https://app.example.test",
            "addendum": (
                "Correction: the staging host staging.example.test shares the production "
                "database, so cross-tenant testing is in scope there too."
            ),
        },
    )
    check("threat_model_amend", amended.get("success") is True, str(amended)[:300])

    # --- todos -------------------------------------------------------------
    check(
        "todo_create",
        (
            await call(
                session,
                "todo_create",
                {"todos": json.dumps([{"title": "map surface", "priority": "high"}])},
            )
        ).get("success")
        is True,
    )
    todos = await call(session, "todo_list")
    check("todo_list", "map surface" in str(todos), str(todos)[:120])
    todo_id = (todos.get("todos") or [{}])[0].get("id", "") if isinstance(todos, dict) else ""
    if todo_id:
        check(
            "todo_mark_done",
            (await call(session, "todo_mark_done", {"todo_ids": todo_id})).get("success") is True,
        )

    # --- findings ----------------------------------------------------------
    finding = await call(
        session,
        "report_finding",
        {
            "title": "IDOR in GET /api/v1/invoices/{id} exposes other tenants' invoices",
            "severity": "high",
            "description": "Invoice lookup is keyed only by sequential id.",
            "target": "https://app.example.test",
            "endpoint": "/api/v1/invoices/{id}",
            "method": "GET",
            "evidence": 'GET /api/v1/invoices/1042 -> 200 {"owner":"other@example.test"}',
            "impact": (
                "Any registered user reads any tenant's invoice.\n"
                "Data Classification: Financial records\n"
                "Mutability: Read-Only\n"
                "Blast Radius: All tenants\n"
                "Containment: Requires a valid session"
            ),
            "technical_analysis": "The handler loads by id without an owner predicate.",
            "poc_description": "Authenticate as user A and request user B's invoice id.",
            "remediation_steps": (
                "1. Scope the query by tenant. 2. Deny by default. 3. Add a regression test."
            ),
            "confidence": "high",
            "confidence_rationale": "Reproduced twice with two accounts.",
            "counterevidence": "Ids could be unguessable; the response shows sequential ids.",
            "severity_change_conditions": (
                "Critical if the list endpoint also leaks across tenants."
            ),
            "cwe": "CWE-639",
            "cvss": "7.1",
            "cvss_breakdown": {"AV": "N", "AC": "L", "PR": "L", "UI": "N"},
            "fix_effort": "low",
            "http_exchange_ids": ["1234"],
            "code_locations": [{"file": "api/invoices.py", "start_line": 42}],
        },
    )
    finding_id = finding.get("finding_id", "")
    check("report_finding", finding_id.startswith("vuln-"), str(finding)[:200])

    dupe = await call(
        session,
        "report_finding",
        {
            "title": "IDOR in GET /api/v1/invoices/{id} exposes other tenants' invoices",
            "endpoint": "/api/v1/invoices/{id}",
        },
    )
    check(
        "duplicate finding is suppressed", dupe.get("duplicate_of") == finding_id, str(dupe)[:160]
    )

    check("report_list", (await call(session, "report_list")).get("count") == 1)
    check(
        "report_get",
        "invoices" in str(await call(session, "report_get", {"report_id": finding_id})),
    )
    check(
        "report_update",
        (
            await call(
                session,
                "report_update",
                {
                    "report_id": finding_id,
                    "fields": {"severity": "critical"},
                    "update_reason": "re-tested impact",
                },
            )
        ).get("updated")
        is True,
    )
    check(
        "severity change persisted",
        "critical" in str(await call(session, "report_get", {"report_id": finding_id})).lower(),
    )

    # withdraw a second finding before close, leaving the audit trail intact
    throwaway = await call(
        session,
        "report_finding",
        {
            "title": "Verbose stack trace on /api/v1/health",
            "severity": "low",
            "endpoint": "/api/v1/health",
            "evidence": "GET /api/v1/health -> 500 with a traceback",
        },
    )
    removed = await call(
        session,
        "report_delete",
        {
            "report_id": throwaway.get("finding_id", ""),
            "delete_reason": "re-test showed a generic error page",
        },
    )
    check("report_delete", removed.get("deleted") is True, str(removed)[:160])
    check(
        "delete requires a reason",
        (await call(session, "report_delete", {"report_id": finding_id, "delete_reason": ""})).get(
            "deleted"
        )
        is False,
    )

    # --- artifacts ---------------------------------------------------------
    run_dirs = sorted((run_root).glob("runscan-*"))
    check("a run directory was created", bool(run_dirs), str(run_root))
    run_dir = run_dirs[-1] if run_dirs else run_root
    for name in (
        "vulnerabilities.json",
        "vulnerabilities.csv",
        "findings.sarif",
        "coverage.json",
        "run.json",
    ):
        check(f"artifact {name}", (run_dir / name).is_file())
    check("per-finding markdown", (run_dir / "vulnerabilities" / f"{finding_id}.md").is_file())

    vulns = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    check(
        "vulnerabilities.json holds one finding",
        len(vulns) == 1 and vulns[0]["id"] == finding_id,
        str([v.get("id") for v in vulns]),
    )
    sarif = json.loads((run_dir / "findings.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0].get("results", [])
    check("SARIF 2.1.0", sarif.get("version") == "2.1.0", sarif.get("version"))
    check(
        "SARIF carries the finding as an error",
        any(r.get("level") == "error" for r in results),
        f"results={len(results)}",
    )
    check(
        "SARIF carries coverage rows as informational",
        any(r.get("level") == "none" for r in results),
        f"results={len(results)}",
    )
    # --- close -------------------------------------------------------------
    closed = await call(
        session,
        "finish_report",
        {
            "executive_summary": "One high-impact access-control flaw confirmed.",
            "methodology": "Authenticated replay of invoice reads across two accounts.",
            "technical_analysis": "The invoice handler lacks a tenant predicate.",
            "recommendations": "Scope reads by tenant and add a regression test.",
            "target": "https://app.example.test",
        },
    )
    report_path = Path(str(closed.get("report", "")))
    check("finish_report wrote the report", report_path.is_file(), str(closed)[:200])
    if report_path.is_file():
        text = report_path.read_text(encoding="utf-8")
        check("report mentions the finding", "invoices" in text)
        check("report includes the attack-surface map", "```mermaid" in text)
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    check("run.json completed", record.get("status") == "completed", str(record.get("status")))
    check("run.json carries scan_results", bool(record.get("scan_results")))
    check(
        "run.json records the target",
        any("app.example.test" in str(t) for t in record.get("targets_info", [])),
    )
    check("notes persisted in .state", (run_dir / ".state" / "notes.json").is_file())
    check("coverage persisted in .state", (run_dir / ".state" / "coverage.json").is_file())

    # --- optional container half ------------------------------------------
    if with_sandbox:
        health = await call(session, "sandbox_health")
        check("sandbox_health", health.get("docker") == "ok", str(health)[:200])
        check("sandbox image present", health.get("image_present") is True, str(health)[:200])
        executed = await call(
            session,
            "sandbox_exec",
            {"command": "echo smoke-ok && nmap --version | head -n 2", "timeout_sec": 120},
        )
        check(
            "sandbox_exec runs the Kali toolbelt",
            executed.get("exit_code") == 0,
            str(executed)[:200],
        )


async def main() -> int:
    parser = argparse.ArgumentParser(description="Strix MCP parity check")
    parser.add_argument(
        "--with-sandbox", action="store_true", help="also boot the Kali container and run one exec"
    )
    opts = parser.parse_args()

    run_root = Path(tempfile.mkdtemp(prefix="strix-mcp-smoke-")) / "strix_runs"
    env = os.environ.copy()
    env.pop("OPENAI_API_KEY", None)
    env.pop("STRIX_LLM", None)
    env["STRIX_MCP_RUNS_DIR"] = str(run_root)
    env["STRIX_MCP_SCAN_ID"] = "smoketest"

    params = StdioServerParameters(
        command=_venv_python(),
        args=[str(ROOT / "mcp" / "server.py")],
        cwd=str(ROOT),
        env=env,
    )

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await run(session, run_root, opts.with_sandbox)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED:")
        for item in FAILURES:
            print(f"  - {item}")
        return 1
    print("ALL PARITY CHECKS PASSED")
    print(f"run dir: {run_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
