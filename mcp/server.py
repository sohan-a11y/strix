"""Strix MCP server - the muscle behind OpenCode agents.

This process exposes Strix's pentest sandbox (a Kali toolbelt container:
nmap, sqlmap, ffuf, katana, nuclei, chromium...) and the finding/report
writers over the Model Context Protocol, via stdio.

Zero LLM keys: nothing here talks to a model API. The "brain" is whatever
agent connects to this server (e.g. an OpenCode agent).

Env vars:
    STRIX_MCP_SCAN_ID   sandbox session id (default: runscan)
    STRIX_IMAGE         sandbox image override (Strix's RuntimeSettings alias)
    STRIX_MCP_RUNS_DIR  base dir for run artifacts (default: ./strix_runs)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging must go to stderr only: stdout is the stdio MCP transport.
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.environ.get("STRIX_MCP_LOG_LEVEL", "INFO"),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("strix-mcp")

_SCAN_ID = os.environ.get("STRIX_MCP_SCAN_ID", "runscan")

_AGENT_BROWSER_BIN = "/home/pentester/.npm-global/bin/agent-browser"

_MAX_STREAM_CHARS = 240_000
_MAX_FILE_CHARS = 400_000

mcp = FastMCP(
    "strix",
    instructions=(
        "Strix pentest sandbox over MCP. Always call strix_sandbox_health "
        "first: on first use it boots the Kali sandbox container (may take a "
        "minute if the image still needs a pull). Run every probe through "
        "strix_sandbox_exec (nmap/sqlmap/ffuf/curl/etc. are preinstalled); "
        "drive web apps with the strix_browser convenience wrapper or "
        "directly via the agent-browser CLI inside the sandbox. Save real, "
        "evidence-backed findings with strix_report_finding and close the "
        "engagement with strix_finish_report. Only operate on targets the "
        "operator is authorized to test."
    ),
)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _runs_base() -> Path:
    base = Path(os.environ.get("STRIX_MCP_RUNS_DIR", "") or Path.cwd() / "strix_runs")
    base.mkdir(parents=True, exist_ok=True)
    return base


_RUN_DIR: Path | None = None


def _run_dir() -> Path:
    global _RUN_DIR
    if _RUN_DIR is None:
        _RUN_DIR = _runs_base() / f"runscan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        (_RUN_DIR / "vulnerabilities").mkdir(parents=True, exist_ok=True)
        logger.info("Run directory: %s", _RUN_DIR)
    return _RUN_DIR


_FINDING_SEQ = 0
_FINDINGS_FILE = "findings.json"


async def _session() -> Any:
    """Ensure the Strix sandbox session exists and return it."""
    from strix.config import load_settings
    from strix.runtime import session_manager

    bundle = await session_manager.create_or_reuse(
        _SCAN_ID,
        image=load_settings().runtime.image,
        local_sources=[],
    )
    return bundle["session"]


def _clamp_text(value: str, limit: int = _MAX_STREAM_CHARS) -> tuple[str, bool]:
    """Keep the head and tail of oversized output, marking the cut."""
    if len(value) <= limit:
        return value, False
    half = limit // 2
    keep_head = value[:half]
    keep_tail = value[-half:]
    return (
        f"{keep_head}\n\n[... output truncated: {len(value) - limit} chars dropped ...]\n\n{keep_tail}",
        True,
    )


def _exec_result(result: Any) -> dict[str, Any]:
    stdout, stdout_cut = _clamp_text(result.stdout.decode("utf-8", errors="replace"))
    stderr, stderr_cut = _clamp_text(result.stderr.decode("utf-8", errors="replace"))
    out: dict[str, Any] = {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": result.exit_code,
    }
    if stdout_cut or stderr_cut:
        out["truncated"] = True
    return out


def _load_findings() -> list[dict[str, Any]]:
    findings_path = _run_dir() / _FINDINGS_FILE
    if not findings_path.exists():
        return []
    try:
        loaded = json.loads(findings_path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, list) else []
    except Exception:  # noqa: BLE001 - corrupted file: start a fresh list
        return []


def _title_tokens(title: str) -> set[str]:
    import re

    return {
        token
        for token in re.findall(r"[a-z0-9]+", title.lower())
        if len(token) > 3
    }


def _duplicate_of(title: str) -> str | None:
    """Best-effort duplicate check: token-overlap with existing titles.

    Deliberately blunt (cosine-free jaccard) so independent retries of the
    same engagement do not silently multiply findings. Runs of a genuinely
    new attack surface are rarely >50% token-identical.
    """
    probes = _title_tokens(title)
    if not probes:
        return None
    for entry in _load_findings():
        existing = _title_tokens(str(entry.get("title", "")))
        if not existing:
            continue
        overlap = len(probes & existing) / len(probes | existing)
        if overlap >= 0.5:
            return str(entry.get("id"))
    return None


def _inside_path(path: str) -> str:
    """Normalize sandbox file paths into the /workspace tree."""
    if not path.startswith("/"):
        path = f"/workspace/{path}"
    normalized = str(PurePosixPath(path))
    if ".." in PurePosixPath(normalized).parts:
        raise ValueError("Relative parent paths are not allowed")
    return normalized


# ---------------------------------------------------------------------------
# Sandbox lifecycle + execution
# ---------------------------------------------------------------------------


@mcp.tool()
async def sandbox_health() -> dict[str, Any]:
    """Check Docker, the sandbox image, and the scan session state.

    Call this first. If image_present is false, tell the operator to run
    setup.ps1 (or docker pull the image from RuntimeSettings) before
    scanning.
    """
    info: dict[str, Any] = {"docker": "unknown", "image": "unknown", "session": "unknown"}
    client = None
    image: str | None = None
    try:
        from strix.runtime.docker_connection import connect_docker

        client = connect_docker()
        info["docker"] = f"ok ({client.version()['Version']})"
    except Exception as exc:  # noqa: BLE001 - report anything to the agent
        info["docker"] = f"error: {exc}"
        logger.warning("Docker health check failed", exc_info=True)
        return info
    try:
        from strix.config import load_settings

        image = load_settings().runtime.image
    except Exception:  # noqa: BLE001
        image = None
    if image:
        info["image"] = image
        try:
            client.images.get(image)
            info["image_present"] = True
        except Exception:  # noqa: BLE001
            info["image_present"] = False
            info["image_hint"] = (
                "Run docker pull on the image above, or setup.ps1 to refresh it."
            )
    from strix.runtime import session_manager

    cached = getattr(session_manager, "_SESSION_CACHE", {}).get(_SCAN_ID)
    info["session"] = "running" if cached is not None else "not_started (created on first exec)"
    return info


@mcp.tool()
async def sandbox_exec(
    command: str,
    timeout_sec: int = 300,
    workdir: str = "",
) -> dict[str, Any]:
    """Run a shell command inside the Kali sandbox container.

    The container has the full Strix toolbelt: nmap, ncat, sqlmap, nuclei,
    subfinder, naabu, ffuf, katana, httpx, gospider, dirsearch, arjun,
    wapiti, wafw00f, trufflehog, trivy, curl, python3, chromium and the
    agent-browser CLI. Traffic is routed through the in-container Caido
    proxy except for localhost.

    Args:
        command: shell command string (bash), e.g.
            'nmap -sV --top-ports 200 -T3 <host>' or 'curl -s -i <url>'.
        timeout_sec: wall-clock timeout, clamped to 5..3600.
        workdir: optional directory to cd into (default /workspace).
    """
    timeout = max(5, min(int(timeout_sec), 3600))
    cmd = command.strip()
    if not cmd:
        return {"error": "empty command"}
    if workdir:
        cmd = f"cd {shlex.quote(_inside_path(workdir))} && {cmd}"
    session = await _session()
    try:
        result = await session.exec("bash", "-c", cmd, timeout=float(timeout), shell=False)
    except TimeoutError:
        return {"error": f"command timed out after {timeout}s"}
    return _exec_result(result)


@mcp.tool()
async def sandbox_write_file(path: str, content: str) -> dict[str, Any]:
    """Write a text file inside the sandbox (relative paths are rooted at /workspace)."""
    if len(content) > 1_000_000:
        return {"error": "content too large (1 MB cap)"}
    target = _inside_path(path)
    parent = str(PurePosixPath(target).parent)
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    session = await _session()
    result = await session.exec(
        "bash",
        "-c",
        f"mkdir -p {shlex.quote(parent)} && echo {encoded} | base64 -d > {shlex.quote(target)}",
        timeout=60.0,
        shell=False,
    )
    return _exec_result(result)


@mcp.tool()
async def sandbox_read_file(path: str) -> dict[str, Any]:
    """Read a text file from the sandbox (relative paths are rooted at /workspace)."""
    target = _inside_path(path)
    session = await _session()
    result = await session.exec(
        "bash",
        "-c",
        f"base64 -w0 {shlex.quote(target)}",
        timeout=60.0,
        shell=False,
    )
    out = _exec_result(result)
    if out.get("exit_code") != 0:
        out["error"] = out.get("stderr") or f"could not read {target}"
        out.pop("stdout", None)
        out.pop("stderr", None)
        return out
    raw = base64.b64decode(out["stdout"].strip())
    out.pop("stdout", None)
    out.pop("stderr", None)
    try:
        text, clipped = _clamp_text(raw.decode("utf-8"), _MAX_FILE_CHARS)
        out["content"] = text
        if clipped:
            out["truncated"] = True
    except UnicodeDecodeError:
        out["content_base64"] = base64.b64encode(raw[:_MAX_FILE_CHARS]).decode("ascii")
        out["note"] = "binary content (or undecodable text): base64 encoded, capped"
    return out


# ---------------------------------------------------------------------------
# Browser convenience wrapper (agent-browser CLI inside the sandbox)
# ---------------------------------------------------------------------------


@mcp.tool()
async def browser(action: str, args: str = "", timeout_sec: int = 120) -> dict[str, Any]:
    """Drive Chromium in the sandbox through the agent-browser CLI.

    Common actions:
        open <url>          navigate (e.g. browser('open', 'http://h/'))
        snapshot -i         accessibility tree with @eN element refs
        click @e3           click an element ref
        fill @e5 'text'     set a field's value
        get text @e9        read an element's text
        get title / get url read page metadata
        screenshot          save PNG (path printed in stdout)
        press Enter, scroll, wait -n3, etc.
    """
    if any(ch in action for ch in "&;|`$><\\\n"):
        return {"error": "action may not contain shell metacharacters"}
    parts = [shlex.quote(action)]
    parts.extend(shlex.split(args))
    cmd = shlex.join([_AGENT_BROWSER_BIN, *parts])
    timeout = max(5, min(int(timeout_sec), 600))
    session = await _session()
    try:
        result = await session.exec("bash", "-c", cmd, timeout=float(timeout), shell=False)
    except TimeoutError:
        return {
            "error": f"browser action timed out after {timeout}s",
            "hint": "re-run 'snapshot -i' or re-open the page",
        }
    out = _exec_result(result)
    if out.get("exit_code") != 0 and out.get("stderr"):
        out["hint"] = (
            "common fixes: open <url> first; use snapshot -i for fresh @e refs"
        )
    return out


# ---------------------------------------------------------------------------
# Findings + final report (Strix-format artifacts on the host)
# ---------------------------------------------------------------------------


@mcp.tool()
async def report_finding(
    title: str,
    severity: str = "medium",
    description: str = "",
    target: str = "",
    endpoint: str = "",
    method: str = "",
    evidence: str = "",
    impact: str = "",
    technical_analysis: str = "",
    poc_description: str = "",
    poc_script_code: str = "",
    remediation_steps: str = "",
    confidence: str = "",
    cwe: str = "",
    cve: str = "",
    cvss: str = "",
) -> dict[str, Any]:
    """Record one confirmed vulnerability in Strix finding format.

    Every field should carry real observation: paste the actual
    request/response as evidence, not speculation. Returns the finding id
    and the artifact path. Re-scans of the same surface are deduplicated:
    a title that is >=50% token-identical to an existing finding returns
    that finding's id instead of creating a new entry.
    """
    from strix.report.writer import atomic_write_text, render_vulnerability_md

    dupe = _duplicate_of(title)
    if dupe is not None:
        return {"finding_id": dupe, "duplicate_of": dupe, "note": "already recorded"}

    global _FINDING_SEQ
    entries = _load_findings()
    _FINDING_SEQ = max(_FINDING_SEQ, len(entries)) + 1
    finding_id = f"VULN-{_FINDING_SEQ:03d}"

    report: dict[str, Any] = {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "finding_class": "dynamic",
        "description": description,
        "target": target,
        "endpoint": endpoint,
        "method": method,
        "evidence": evidence,
        "impact": impact,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "confidence": confidence,
        "cwe": cwe,
        "cve": cve,
        "cvss": cvss,
    }
    entries.append(report)
    run_dir = _run_dir()
    findings_path = run_dir / _FINDINGS_FILE
    atomic_write_text(findings_path, json.dumps(entries, indent=2) + "\n")
    vuln_path = run_dir / "vulnerabilities" / f"{finding_id}.md"
    atomic_write_text(vuln_path, render_vulnerability_md(report))
    return {"finding_id": finding_id, "path": str(vuln_path)}


@mcp.tool()
async def finish_report(
    executive_summary: str,
    methodology: str = "",
    technical_analysis: str = "",
    recommendations: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Write the final penetration_test_report.md and close the run.

    Call once at the end: executive summary is what a non-technical reader
    needs; methodology explains the phases; technical_analysis describes
    what was tested and how; recommendations are ordered fixes.
    """
    run_dir = _run_dir()
    findings = _load_findings()

    lines: list[str] = [
        "# Penetration Test Report\n",
        f"**Target:** {target or 'unspecified'}\n",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
        f"**Run dir:** {run_dir}\n",
        "## Executive Summary\n",
        executive_summary,
        "",
        "## Findings Overview\n",
        f"Total confirmed findings: {len(findings)}\n",
    ]
    if findings:
        lines.append("| ID | Severity | Title | Endpoint |")
        lines.append("|---|---|---|---|")
        for item in findings:
            lines.append(
                f"| {item.get('id', '-')} | {str(item.get('severity', '-')).upper()} "
                f"| {item.get('title', '-')} | {item.get('endpoint') or '-'} |"
            )
        lines.append("")
    lines.append("## Methodology\n")
    lines.append(methodology or "Not documented.")
    lines.append("")
    lines.append("## Technical Analysis\n")
    lines.append(technical_analysis or "Not documented.")
    lines.append("")
    lines.append("## Recommendations\n")
    lines.append(recommendations or "No recommendations recorded.")
    lines.append("")
    report_path = run_dir / "penetration_test_report.md"
    from strix.report.writer import atomic_write_text

    atomic_write_text(report_path, "\n".join(lines))
    return {
        "report": str(report_path),
        "findings": len(findings),
        "run_dir": str(run_dir),
        "note": "run closed; call sandbox_stop when the session is done",
    }


@mcp.tool()
async def sandbox_stop() -> dict[str, Any]:
    """Stop and remove the sandbox container for this run (cleanup)."""
    from strix.runtime import session_manager

    await session_manager.cleanup(_SCAN_ID)
    return {"stopped": True, "scan_id": _SCAN_ID}


if __name__ == "__main__":
    mcp.run()
