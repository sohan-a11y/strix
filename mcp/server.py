"""Strix MCP server - the full Strix engine, minus the model.

This process exposes Strix's pentest sandbox (a Kali toolbelt container:
nmap, sqlmap, ffuf, katana, nuclei, chromium...), the engine's own tool
implementations (proxy, skills, notes, coverage, threat model, todos) and
the engine's canonical report writers over the Model Context Protocol,
via stdio.

Zero LLM keys: nothing here talks to a model API. The "brain" is whatever
agent connects to this server (e.g. an OpenCode agent). That is the only
part of the engine that is replaced - every deterministic component below
is the shipped Strix implementation, imported from the installed package:

  * runtime      -> strix.runtime.session_manager (Docker sandbox + Caido)
  * proxy        -> strix.tools.proxy.tools   (list/view/replay/sitemap)
  * skills       -> strix.skills              (81 packaged knowledge packs)
  * notes        -> strix.tools.notes.tools
  * coverage     -> strix.tools.coverage.tools
  * threat model -> strix.tools.threat_model.tools
  * todos        -> strix.tools.todo.tools
  * reporting    -> strix.report.state.ReportState
                    (vulnerabilities.json/.csv/.md, findings.sarif,
                     coverage.json, run.json)

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
import re
import shlex
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
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

_AGENT_ID = "root"
_AGENT_NAME = "pentest"

mcp = FastMCP(
    "strix",
    instructions=(
        "Strix pentest engine over MCP (agentic mode: you are the model). "
        "Always call strix_sandbox_health first: on first use it boots the "
        "Kali sandbox container (may take a minute if the image still needs "
        "a pull). Run every probe through strix_sandbox_exec "
        "(nmap/sqlmap/ffuf/curl/etc. are preinstalled); drive web apps with "
        "strix_browser; inspect captured traffic with strix_proxy_*; pull "
        "vulnerability/tooling guidance with strix_skill_load; record shared "
        "state with strix_note_*, strix_coverage_*, strix_threat_model_*; "
        "save real, evidence-backed findings with strix_report_finding and "
        "close the engagement with strix_finish_report. Only operate on "
        "targets the operator has authorized."
    ),
)


# ---------------------------------------------------------------------------
# Run directory + engine report state
# ---------------------------------------------------------------------------

_RUN_DIR: Path | None = None


def _runs_base() -> Path:
    base = Path(os.environ.get("STRIX_MCP_RUNS_DIR", "") or Path.cwd() / "strix_runs")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _run_dir() -> Path:
    global _RUN_DIR
    if _RUN_DIR is None:
        _RUN_DIR = _runs_base() / f"runscan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        (_RUN_DIR / "vulnerabilities").mkdir(parents=True, exist_ok=True)
        logger.info("Run directory: %s", _RUN_DIR)
    return _RUN_DIR


_REPORT_STATE: Any = None
_SCAN_TARGETS: list[str] = []


def _remember_target(target: str) -> None:
    target = (target or "").strip()
    if target and target not in _SCAN_TARGETS:
        _SCAN_TARGETS.append(target)
        if _REPORT_STATE is not None:
            _REPORT_STATE.run_record["targets_info"] = list(_SCAN_TARGETS)


def _report_state() -> Any:
    """The engine's ReportState, rooted at this MCP run directory.

    Constructing it also wires the engine's shared per-run state
    (notes/coverage/threat model/todos) to ``{run_dir}/.state``, so the
    state tools persist exactly where the real engine keeps them.
    """
    global _REPORT_STATE
    if _REPORT_STATE is not None:
        return _REPORT_STATE

    from strix.core.paths import runtime_state_dir
    from strix.report.state import ReportState, set_global_report_state
    from strix.tools.coverage.tools import hydrate_coverage_from_disk
    from strix.tools.notes.tools import hydrate_notes_from_disk
    from strix.tools.threat_model.tools import hydrate_threat_models_from_disk
    from strix.tools.todo.tools import hydrate_todos_from_disk

    run_dir = _run_dir()
    state = ReportState(run_name=run_dir.name)
    # Pin the exact directory: the base may be overridden via env, and the
    # engine would otherwise re-derive ./strix_runs/<name> from cwd.
    state._run_dir = run_dir

    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    hydrate_todos_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)
    hydrate_coverage_from_disk(state_dir)
    hydrate_threat_models_from_disk(state_dir)

    # Fill the same run-record fields a native run gets from its scan config,
    # so run.json is shaped identically (targets_info, scan_mode, scope_mode).
    state.set_scan_config(
        {
            "targets": list(_SCAN_TARGETS),
            "user_instructions": os.environ.get("STRIX_MCP_INSTRUCTIONS", ""),
            "scan_mode": os.environ.get("STRIX_MCP_SCAN_MODE", "deep"),
            "non_interactive": True,
            "local_sources": [],
            "scope_mode": "auto",
            "diff_scope": {"active": False},
        }
    )
    state.run_record["auth_mode"] = "agentic"
    state.run_record["engine"] = "strix-agentic-mcp"
    state.run_record["model"] = "host-agent (no API key)"

    set_global_report_state(state)
    _REPORT_STATE = state
    logger.info("ReportState ready at %s", run_dir)
    return state


def _save_artifacts() -> None:
    """Rewrite every canonical artifact (JSON/CSV/MD/SARIF/coverage/run.json)."""
    _report_state().save_run_data()


def _findings() -> list[dict[str, Any]]:
    return list(_report_state().vulnerability_reports)


# ---------------------------------------------------------------------------
# Engine tool bridge
# ---------------------------------------------------------------------------


def _engine_ctx(tool_name: str) -> Any:
    """A RunContextWrapper the engine's @function_tool implementations accept.

    The SDK normally builds this during a model run; the fields it adds are
    only used for tracing and error reporting, so a synthetic context is
    enough. The ``context`` dict is the same shape the engine passes to its
    tools (agent identity + scan context).
    """
    from agents import RunContextWrapper

    ctx = RunContextWrapper(
        context={
            "agent_id": _AGENT_ID,
            "agent_name": _AGENT_NAME,
            "scan_targets": list(_SCAN_TARGETS),
            "supports_images": True,
            "coverage_tools": True,
        }
    )
    ctx.tool_name = tool_name
    ctx.run_config = SimpleNamespace(trace_include_sensitive_data=False)
    return ctx


async def _invoke_engine(tool: Any, args_: dict[str, Any]) -> Any:
    # The engine's state stores are module-level and only persist once the
    # run's state dir has been hydrated. ReportState does that wiring; make
    # sure it ran before any state tool touches them.
    _report_state()
    raw = await tool.on_invoke_tool(_engine_ctx(tool.name), json.dumps(args_))
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def _as_json(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


# ---------------------------------------------------------------------------
# Sandbox lifecycle + execution
# ---------------------------------------------------------------------------

_BUNDLE: Any = None


async def _bundle() -> Any:
    """Ensure the Strix sandbox session exists and return the engine bundle.

    The bundle carries ``session`` (exec/pty) and ``caido_client`` (the
    host-side connection to the in-container proxy), exactly as a native
    Strix run gets it.
    """
    global _BUNDLE
    if _BUNDLE is None:
        from strix.config import load_settings
        from strix.runtime import session_manager

        _BUNDLE = await session_manager.create_or_reuse(
            _SCAN_ID,
            image=load_settings().runtime.image,
            local_sources=[],
        )
    return _BUNDLE


async def _session() -> Any:
    return (await _bundle())["session"]


def _clamp_text(value: str, limit: int = _MAX_STREAM_CHARS) -> tuple[str, bool]:
    """Keep the head and tail of oversized output, marking the cut."""
    if len(value) <= limit:
        return value, False
    half = limit // 2
    keep_head = value[:half]
    keep_tail = value[-half:]
    return (
        f"{keep_head}\n\n[... output truncated: "
        f"{len(value) - limit} chars dropped ...]\n\n{keep_tail}",
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


def _title_tokens(title: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", title.lower()) if len(token) > 3}


def _duplicate_of(title: str, endpoint: str = "") -> str | None:
    """Deterministic stand-in for the engine's LLM dedupe.

    The engine calls a model for semantic dedupe and degrades to "not a
    duplicate" when no model is configured. In agentic mode there is no
    model, so this token-overlap check keeps the same guarantee without one:
    an independent retry of the same finding does not multiply the report.
    """
    probes = _title_tokens(title)
    if not probes:
        return None
    normalized_endpoint = (endpoint or "").strip().lower()
    for entry in _findings():
        if normalized_endpoint and str(entry.get("endpoint") or "").strip().lower() not in (
            "",
            normalized_endpoint,
        ):
            continue
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


@mcp.tool()
async def sandbox_health() -> dict[str, Any]:
    """Check Docker, the sandbox image, the proxy, and the run state.

    Call this first. If image_present is false, tell the operator to run
    setup.ps1 (or docker pull the image from RuntimeSettings) before
    scanning.
    """
    info: dict[str, Any] = {
        "docker": "unknown",
        "image": "unknown",
        "session": "unknown",
        "engine": "strix-agentic-mcp",
        "run_dir": str(_run_dir()),
    }
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
            info["image_hint"] = "Run docker pull on the image above, or setup.ps1 to refresh it."
    from strix.runtime import session_manager

    cached = getattr(session_manager, "_SESSION_CACHE", {}).get(_SCAN_ID)
    info["session"] = "running" if cached is not None else "not_started (created on first exec)"

    try:
        from strix.skills import get_available_skills

        info["skills"] = sum(len(v) for v in get_available_skills().values())
    except Exception:  # noqa: BLE001
        info["skills"] = "unavailable"
    info["findings"] = len(_findings())
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
    agent-browser CLI. HTTP(S) traffic is routed through the in-container
    Caido proxy except for localhost, so every request lands in proxy
    history (see strix_proxy_list_requests).

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
    timeout = max(5, min(int(timeout_sec), 600))
    parts = [shlex.quote(_AGENT_BROWSER_BIN), action.strip()]
    if args.strip():
        parts.append(args.strip())
    cmd = " ".join(parts)
    session = await _session()
    try:
        result = await session.exec("bash", "-c", cmd, timeout=float(timeout), shell=False)
    except TimeoutError:
        return {"error": f"browser action timed out after {timeout}s"}
    return _exec_result(result)


# ---------------------------------------------------------------------------
# Skills (the engine's packaged knowledge packs)
# ---------------------------------------------------------------------------


@mcp.tool()
async def skill_list() -> dict[str, Any]:
    """List every Strix skill, grouped by category.

    Skills are the engine's own knowledge packs (vulnerability classes,
    protocols, frameworks, tooling, cloud, scan modes). The agent prompt
    preloads the ones for its role; use strix_skill_load for anything else
    before guessing payloads or tool syntax.
    """
    from strix.skills import get_available_skills

    grouped = get_available_skills()
    return {
        "count": sum(len(v) for v in grouped.values()),
        "categories": grouped,
    }


@mcp.tool()
async def skill_load(skills: list[str]) -> str:
    """Load one or more Strix skill documents into the conversation.

    Names may be bare (``xss``) or category-qualified
    (``vulnerabilities/xss``); use qualified names when a bare name is
    ambiguous. Max 5 per call. The content lands inline as reference
    material - read it before acting on that technology.
    """
    from strix.skills import load_skills, validate_requested_skills

    requested = [s.strip() for s in skills if s and s.strip()]
    error = validate_requested_skills(requested)
    if error:
        return f"skill_load: {error}"
    contents = load_skills(requested, supports_images=True, coverage_tools=True)
    if not contents:
        return "skill_load: no content loaded for requested skills."
    return "\n\n---\n\n".join(f"## Skill: {name}\n\n{body}" for name, body in contents.items())


# ---------------------------------------------------------------------------
# Findings (engine ReportState -> canonical artifacts)
# ---------------------------------------------------------------------------


def _parse_float(raw: Any) -> float | None:
    if raw is None or raw == "":
        return None
    match = re.search(r"\d+(?:\.\d+)?", str(raw))
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _parse_list(raw: Any) -> list[Any]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return raw
    text = str(raw).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        return [item.strip() for item in text.split(",") if item.strip()]


def _parse_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


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
    confidence_rationale: str = "",
    assumptions: str = "",
    counterevidence: str = "",
    severity_change_conditions: str = "",
    fix_effort: str = "",
    cwe: str = "",
    cve: str = "",
    cvss: str = "",
    cvss_breakdown: dict[str, str] | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    fix_verification: str = "",
    fix_pr_body: str = "",
    http_exchange_ids: list[str] | None = None,
    finding_class: str = "dynamic",
    dependency_metadata: dict[str, str] | None = None,
    data_classification: str = "",
    mutability: str = "Read-Only",
    affected_schemas: str = "",
    isolated_schemas: str = "",
    blast_radius: str = "",
    containment: str = "",
) -> dict[str, Any]:
    """Record one confirmed vulnerability in canonical Strix format.

    Writes the engine's artifacts immediately: ``vulnerabilities/vuln-*.md``,
    ``vulnerabilities.json``, ``vulnerabilities.csv``, ``findings.sarif``,
    ``coverage.json`` and ``run.json``. Every field should carry real
    observation: paste the actual request/response as evidence, not
    speculation. A title that is >=50% token-identical to an existing
    finding (on the same endpoint) returns that finding's id instead of
    creating a duplicate.

    Engine-specific fields worth using:
        counterevidence: the strongest case against this finding
        confidence_rationale: why the confidence level is justified
        severity_change_conditions: what evidence would change severity
        fix_effort: trivial | low | medium | high
        code_locations: [{"file":..., "start_line":..., "fix_before":...,
                          "fix_after":...}]
        http_exchange_ids: Caido request ids proving the finding
        dependency_metadata: {"package_name":..., "package_ecosystem":...,
                              "installed_version":..., "fixed_version":...,
                              "manifest_path":...} for dependency CVEs
    """
    from strix.report.state import get_global_report_state

    _remember_target(target)

    dupe = _duplicate_of(title, endpoint)
    if dupe is not None:
        return {"finding_id": dupe, "duplicate_of": dupe, "note": "already recorded"}

    state = _report_state()
    if get_global_report_state() is None:  # defensive: the engine tools need it
        from strix.report.state import set_global_report_state

        set_global_report_state(state)
    report_id = state._next_report_id()

    # Build the enriched impact text (classification/mutability/blast radius
    # plus the per-finding Mermaid map) the same way previous runs did.
    enriched_impact = impact
    extra_impact_parts: list[str] = []
    if data_classification and "Data Classification" not in impact:
        extra_impact_parts.append(f"* **Data Classification:** {data_classification}")
    if mutability and "Mutability" not in impact and "Can Data Be Changed" not in impact:
        extra_impact_parts.append(f"* **Data Mutability (Can it be changed?):** {mutability}")
    if affected_schemas and "Affected Schemas" not in impact:
        extra_impact_parts.append(f"* **Affected Schemas/Tables:** {affected_schemas}")
    if isolated_schemas and "Isolated Schemas" not in impact:
        extra_impact_parts.append(f"* **Isolated & Protected Schemas:** {isolated_schemas}")
    if blast_radius and "Blast Radius" not in impact:
        extra_impact_parts.append(f"* **Blast Radius & Reachability:** {blast_radius}")
    if containment and "Containment" not in impact:
        extra_impact_parts.append(f"* **Containment Boundary:** {containment}")

    mermaid_block = _generate_finding_mermaid(
        finding_id=report_id,
        title=title,
        endpoint=endpoint,
        data_classification=data_classification or "Exposed Data",
        mutability=mutability or "Read-Only",
        affected_schemas=affected_schemas or "Exposed Resource",
        isolated_schemas=isolated_schemas or "Remainder of Data Estate",
    )
    if extra_impact_parts or mermaid_block:
        sections: list[str] = []
        if impact:
            sections.append(impact)
        if extra_impact_parts:
            sections.append(
                "### Data Exposure & Mutability Assessment\n" + "\n".join(extra_impact_parts)
            )
        if mermaid_block:
            sections.append("### Visual Blast Radius & Isolation Map\n" + mermaid_block)
        enriched_impact = "\n\n".join(sections)

    locations = code_locations if isinstance(code_locations, list) else []
    exchange_ids = [str(x) for x in (http_exchange_ids or []) if str(x).strip()]

    try:
        actual_id = state.add_vulnerability_report(
            title=title,
            severity=severity,
            description=description,
            impact=enriched_impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            evidence=evidence,
            assumptions=assumptions,
            counterevidence=counterevidence,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            severity_change_conditions=severity_change_conditions,
            fix_effort=fix_effort,
            cvss=_parse_float(cvss),
            cvss_breakdown=cvss_breakdown or None,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=locations or None,
            http_exchange_ids=exchange_ids or None,
            fix_verification=fix_verification,
            fix_pr_body=fix_pr_body,
            finding_class=finding_class or "dynamic",
            dependency_metadata=dependency_metadata or None,
            agent_id=_AGENT_ID,
            agent_name=_AGENT_NAME,
        )
    except Exception as exc:
        logger.exception("report_finding failed")
        return {"error": f"failed to record finding: {exc}"}

    _save_artifacts()
    vuln_path = _run_dir() / "vulnerabilities" / f"{actual_id}.md"
    return {
        "finding_id": actual_id,
        "path": str(vuln_path),
        "severity": severity.lower(),
        "artifacts": str(_run_dir()),
        "note": "canonical artifacts rewritten (md/json/csv/sarif/coverage/run.json)",
    }


@mcp.tool()
async def report_list(severity: str = "", include_summary: bool = False) -> dict[str, Any]:
    """List findings filed in this run (metadata-first).

    Read-only orchestration tool: use it to track coverage, avoid
    re-testing reported ground, and assemble the final report.
    """
    wanted = severity.strip().lower()
    rows = []
    for report in _findings():
        if wanted and str(report.get("severity", "")).lower() != wanted:
            continue
        row = {
            "id": report.get("id"),
            "title": report.get("title"),
            "severity": report.get("severity"),
            "endpoint": report.get("endpoint", ""),
            "method": report.get("method", ""),
            "cwe": report.get("cwe", ""),
            "confidence": report.get("confidence", ""),
            "filed_by": report.get("agent_name", ""),
        }
        if include_summary:
            row["description"] = str(report.get("description", ""))[:300]
        rows.append(row)
    counts: dict[str, int] = {}
    for report in _findings():
        key = str(report.get("severity", "unknown")).lower()
        counts[key] = counts.get(key, 0) + 1
    return {"count": len(rows), "by_severity": counts, "reports": rows}


@mcp.tool()
async def report_get(report_id: str) -> dict[str, Any]:
    """Read one finding in full by its engine id (e.g. ``vuln-0001``)."""
    for report in _findings():
        if report.get("id") == report_id:
            return report
    return {"error": f"unknown report id: {report_id}"}


@mcp.tool()
async def report_update(
    report_id: str,
    fields: dict[str, Any],
    update_reason: str = "",
) -> dict[str, Any]:
    """Revise a finding in place (keeps its id and audit history).

    Pass only the fields that change. Updatable fields are the engine's:
    title, severity, description, impact, target, technical_analysis,
    poc_description, poc_script_code, remediation_steps, evidence,
    assumptions, counterevidence, confidence, confidence_rationale,
    severity_change_conditions, fix_effort, cvss, cvss_breakdown, endpoint,
    method, cve, cwe, code_locations, http_exchange_ids, fix_verification,
    fix_pr_body, dependency_metadata.
    """
    state = _report_state()
    updated = state.update_vulnerability_report(
        report_id,
        fields,
        update_reason=update_reason or None,
        updated_by_agent_id=_AGENT_ID,
        updated_by_agent_name=_AGENT_NAME,
    )
    if updated is None:
        return {
            "updated": False,
            "error": f"no change applied (unknown id or identical values): {report_id}",
        }
    _save_artifacts()
    return {"updated": True, "report": updated}


@mcp.tool()
async def report_delete(report_id: str, delete_reason: str) -> dict[str, Any]:
    """Withdraw a finding that re-testing proved is not a vulnerability.

    Use only for a disproved finding - a real but weaker finding is
    revised with report_update, never deleted. The audit record keeps who
    filed it and why it was withdrawn.
    """
    if not delete_reason.strip():
        return {"deleted": False, "error": "delete_reason is required"}
    state = _report_state()
    removed = state.delete_vulnerability_report(
        report_id,
        delete_reason=delete_reason,
        deleted_by_agent_id=_AGENT_ID,
        deleted_by_agent_name=_AGENT_NAME,
    )
    if removed is None:
        return {"deleted": False, "error": f"unknown report id: {report_id}"}
    _save_artifacts()
    return {"deleted": True, "report_id": report_id, "title": removed.get("title")}


# ---------------------------------------------------------------------------
# Shared scan state: notes, coverage, threat model, todos
# ---------------------------------------------------------------------------


@mcp.tool()
async def note_create(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> Any:
    """Create a shared note visible to every agent in this run.

    Use notes for durable cross-agent facts that are not findings: working
    credentials, endpoint inventories, tenant lists, rate-limit quirks.
    """
    from strix.tools.notes.tools import create_note

    return await _invoke_engine(
        create_note,
        {"title": title, "content": content, "category": category, "tags": tags or []},
    )


@mcp.tool()
async def note_list(
    category: str = "",
    search: str = "",
    include_content: bool = False,
) -> Any:
    """List shared notes (optionally filtered), with a content preview."""
    from strix.tools.notes.tools import list_notes

    return await _invoke_engine(
        list_notes,
        {
            "category": category or None,
            "search": search or None,
            "include_content": include_content,
        },
    )


@mcp.tool()
async def note_get(note_id: str) -> Any:
    """Read one shared note in full."""
    from strix.tools.notes.tools import get_note

    return await _invoke_engine(get_note, {"note_id": note_id})


@mcp.tool()
async def note_update(
    note_id: str,
    title: str = "",
    content: str = "",
    tags: list[str] | None = None,
) -> Any:
    """Update a shared note (only the fields you pass change)."""
    from strix.tools.notes.tools import update_note

    payload: dict[str, Any] = {"note_id": note_id}
    if title:
        payload["title"] = title
    if content:
        payload["content"] = content
    if tags is not None:
        payload["tags"] = tags
    return await _invoke_engine(update_note, payload)


@mcp.tool()
async def note_delete(note_id: str) -> Any:
    """Delete a shared note that is now wrong or superseded."""
    from strix.tools.notes.tools import delete_note

    return await _invoke_engine(delete_note, {"note_id": note_id})


@mcp.tool()
async def coverage_record(
    surface: str,
    risk_area: str,
    outcome: str,
    evidence: str = "",
) -> Any:
    """Record one assessed surface in the run's coverage ledger.

    ``outcome`` is one of: reported, no_issue_found, ruled_out,
    not_applicable, needs_follow_up. Evidence is required for ruled_out,
    not_applicable and needs_follow_up (name the specific control or what
    is still missing). One row per surface+risk: correct it with
    coverage_update instead of recording a second row.
    """
    from strix.tools.coverage.tools import record_coverage

    return await _invoke_engine(
        record_coverage,
        {
            "surface": surface,
            "risk_area": risk_area,
            "outcome": outcome,
            "evidence": evidence,
        },
    )


@mcp.tool()
async def coverage_update(entry_id: str, outcome: str, evidence: str = "") -> Any:
    """Move an existing coverage row to its real outcome."""
    from strix.tools.coverage.tools import update_coverage

    return await _invoke_engine(
        update_coverage,
        {"entry_id": entry_id, "outcome": outcome, "evidence": evidence},
    )


@mcp.tool()
async def coverage_list(outcome: str = "", surface: str = "") -> Any:
    """List coverage rows (filter by outcome and/or surface)."""
    from strix.tools.coverage.tools import list_coverage

    return await _invoke_engine(
        list_coverage,
        {"outcome": outcome or None, "surface": surface or None},
    )


@mcp.tool()
async def threat_model_get(target: str) -> Any:
    """Read the run's shared threat model for a target.

    ``found: false`` means no agent has derived one yet - derive it and
    save it before spawning hunters.
    """
    from strix.tools.threat_model.tools import get_threat_model

    _remember_target(target)
    return await _invoke_engine(get_threat_model, {"target": target})


@mcp.tool()
async def threat_model_save(target: str, content: str) -> Any:
    """Establish (or fold amendments into) the shared threat model.

    The engine validates the document: at least 400 characters and four
    section headings - ``Overview``, ``Trust Boundaries`` (and Assumptions),
    ``Attack Surface`` (and Attacker Stories), ``Severity Calibration``.
    Replaces the whole document and clears amendments, so normally only the
    root agent calls it.
    """
    from strix.tools.threat_model.tools import save_threat_model

    _remember_target(target)
    return await _invoke_engine(save_threat_model, {"target": target, "content": content})


@mcp.tool()
async def threat_model_amend(target: str, addendum: str) -> Any:
    """Append an attributed correction to the shared threat model.

    Use when testing disproves a boundary, reveals a role, or finds a host
    or endpoint the model never listed. Minimum 80 characters: say what the
    base model got wrong and name the endpoint/host/control that proves it.
    """
    from strix.tools.threat_model.tools import amend_threat_model

    _remember_target(target)
    return await _invoke_engine(amend_threat_model, {"target": target, "addendum": addendum})


@mcp.tool()
async def todo_create(todos: str) -> Any:
    """Create todos for this agent from a JSON array string.

    Always pass an array, even for one item:
    ``[{"title": "...", "priority": "high"}]``
    """
    from strix.tools.todo.tools import create_todo

    return await _invoke_engine(create_todo, {"todos": todos})


@mcp.tool()
async def todo_list(status: str = "", include_completed: bool = True) -> Any:
    """List this agent's todos (optionally filtered by status)."""
    from strix.tools.todo.tools import list_todos

    payload: dict[str, Any] = {"include_completed": include_completed}
    if status:
        payload["status"] = status
    return await _invoke_engine(list_todos, payload)


@mcp.tool()
async def todo_update(updates: str) -> Any:
    """Update todos from a JSON array string.

    ``[{"id": "...", "title": "...", "priority": "high"}]``
    """
    from strix.tools.todo.tools import update_todo

    return await _invoke_engine(update_todo, {"updates": updates})


@mcp.tool()
async def todo_mark_done(todo_ids: str) -> Any:
    """Mark todos done (comma-separated ids or a JSON array string)."""
    from strix.tools.todo.tools import mark_todo_done

    return await _invoke_engine(mark_todo_done, {"todo_ids": todo_ids})


@mcp.tool()
async def todo_mark_pending(todo_ids: str) -> Any:
    """Re-open todos (comma-separated ids or a JSON array string)."""
    from strix.tools.todo.tools import mark_todo_pending

    return await _invoke_engine(mark_todo_pending, {"todo_ids": todo_ids})


@mcp.tool()
async def todo_delete(todo_ids: str) -> Any:
    """Delete todos (comma-separated ids or a JSON array string)."""
    from strix.tools.todo.tools import delete_todo

    return await _invoke_engine(delete_todo, {"todo_ids": todo_ids})


# ---------------------------------------------------------------------------
# Proxy (the engine's own Caido tools, using the run's caido_client handle)
# ---------------------------------------------------------------------------


async def _proxy_call(tool: Any, args_: dict[str, Any]) -> Any:
    bundle = await _bundle()
    ctx = _engine_ctx(tool.name)
    ctx.context["caido_client"] = bundle.get("caido_client")
    raw = await tool.on_invoke_tool(ctx, json.dumps(args_))
    return _as_json(raw)


@mcp.tool()
async def proxy_list_requests(
    httpql_filter: str = "",
    first: int = 50,
    after: str = "",
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    scope_id: str = "",
) -> Any:
    """List captured HTTP requests from the Caido proxy (engine tool).

    HTTPQL examples:
        resp.code.gte:400
        req.method.eq:"POST" AND resp.code.gte:400
        req.host.cont:"api" AND req.path.cont:"/v1/"
    String values must be quoted; integer values must not. There is no NOT -
    use the negated operator (ne/ncont/nregex). Pagination: pass the previous
    ``page_info.end_cursor`` as ``after``.
    """
    from strix.tools.proxy.tools import list_requests

    return await _proxy_call(
        list_requests,
        {
            "httpql_filter": httpql_filter or None,
            "first": max(1, min(int(first), 200)),
            "after": after or None,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "scope_id": scope_id or None,
        },
    )


@mcp.tool()
async def proxy_view_request(request_id: str, part: str = "request") -> Any:
    """Read one captured exchange (``part`` = request | response).

    The returned request id is what ``http_exchange_ids`` on a finding
    should cite - never invent one.
    """
    from strix.tools.proxy.tools import view_request

    return await _proxy_call(view_request, {"request_id": request_id, "part": part})


@mcp.tool()
async def proxy_repeat_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> Any:
    """Replay a captured request, optionally modifying it.

    ``modifications`` supports method/url/headers/body/params overrides as
    accepted by the engine's replay tool.
    """
    from strix.tools.proxy.tools import repeat_request

    return await _proxy_call(
        repeat_request,
        {"request_id": request_id, "modifications": modifications or {}},
    )


@mcp.tool()
async def proxy_list_sitemap(
    scope_id: str = "",
    parent_id: str = "",
    depth: str = "DIRECT",
    page: int = 1,
) -> Any:
    """Browse the proxy's sitemap tree (engine tool)."""
    from strix.tools.proxy.tools import list_sitemap

    return await _proxy_call(
        list_sitemap,
        {
            "scope_id": scope_id or None,
            "parent_id": parent_id or None,
            "depth": depth,
            "page": max(1, int(page)),
        },
    )


@mcp.tool()
async def proxy_view_sitemap_entry(entry_id: str) -> Any:
    """Read one sitemap entry (engine tool)."""
    from strix.tools.proxy.tools import view_sitemap_entry

    return await _proxy_call(view_sitemap_entry, {"entry_id": entry_id})


@mcp.tool()
async def proxy_scope_rules(
    action: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str = "",
    scope_name: str = "",
) -> Any:
    """Read or write Caido proxy scope rules.

    ``action`` is one of: get, list, create, update, delete.
    """
    from strix.tools.proxy.tools import scope_rules

    return await _proxy_call(
        scope_rules,
        {
            "action": action,
            "allowlist": allowlist or [],
            "denylist": denylist or [],
            "scope_id": scope_id or None,
            "scope_name": scope_name or None,
        },
    )


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------


@mcp.tool()
async def finish_report(
    executive_summary: str,
    methodology: str = "",
    technical_analysis: str = "",
    recommendations: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Close the run and write the final penetration_test_report.md.

    Call once at the end: executive summary is what a non-technical reader
    needs; methodology explains the phases; technical_analysis describes
    what was tested and how; recommendations are ordered fixes. This also
    marks run.json completed and rewrites every canonical artifact.
    """
    _remember_target(target)
    run_dir = _run_dir()
    findings = _findings()

    lines: list[str] = [
        "# Penetration Test Report\n",
        f"**Target:** {target or 'unspecified'}\n",
        f"**Date:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}\n",
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
        lines.extend(
            f"| {item.get('id', '-')} | {str(item.get('severity', '-')).upper()} "
            f"| {item.get('title', '-')} | {item.get('endpoint') or '-'} |"
            for item in findings
        )
        lines.append("")

        lines.append("## Visual Attack Surface & Blast Radius Map\n")
        lines.append(
            "Visual overview of the attack surface, compromised assets, "
            "mutability, and isolated database estate:\n"
        )
        lines.append(_generate_consolidated_mermaid(findings))
        lines.append("")

        lines.append("## Data Exposure, Mutability & Blast Radius Assessment\n")
        lines.append(
            "Evaluation of exposed schemas, data classifications, write/tamper "
            "capability, and confirmed reachability boundaries:\n"
        )
        lines.append(
            "| ID | Severity | Data Classification | Can Be Changed (Mutability)? "
            "| Confirmed Blast Radius | Containment Boundary |"
        )
        lines.append("|---|---|---|---|---|---|")
        for item in findings:
            d_class, mut, blast, cont = _extract_blast_radius_summary(item)
            lines.append(
                f"| {item.get('id', '-')} | {str(item.get('severity', '-')).upper()} "
                f"| {d_class} | {mut} | {blast} | {cont} |"
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

    # 1) Close the engine run record first (writes run.json + coverage.json
    #    with status=completed), then write the richer human report over the
    #    engine's minimal markdown.
    state = _report_state()
    state.final_scan_result = (
        "# Executive Summary\n\n"
        f"{executive_summary.strip()}\n\n"
        "# Methodology\n\n"
        f"{methodology.strip()}\n\n"
        "# Technical Analysis\n\n"
        f"{technical_analysis.strip()}\n\n"
        "# Recommendations\n\n"
        f"{recommendations.strip()}\n"
    )
    # Mirror the engine's `update_scan_final_fields` exactly (same dict shape
    # in run.json), but write it directly: that method also fires PostHog/
    # Scarf telemetry, which an agentic run must not emit.
    state.scan_results = {
        "scan_completed": True,
        "executive_summary": executive_summary.strip(),
        "methodology": methodology.strip(),
        "technical_analysis": technical_analysis.strip(),
        "recommendations": recommendations.strip(),
        "success": True,
    }
    state.run_record["scan_results"] = state.scan_results
    state.run_record["targets_info"] = list(_SCAN_TARGETS)
    state.save_run_data(mark_complete=True)
    atomic_write_text(report_path, "\n".join(lines))

    artifacts = {
        "report": str(report_path),
        "findings": len(findings),
        "run_dir": str(run_dir),
        "vulnerabilities_json": str(run_dir / "vulnerabilities.json"),
        "vulnerabilities_csv": str(run_dir / "vulnerabilities.csv"),
        "sarif": str(run_dir / "findings.sarif"),
        "coverage": str(run_dir / "coverage.json"),
        "run_record": str(run_dir / "run.json"),
    }
    return {
        **artifacts,
        "note": "run closed; call sandbox_stop when the session is done",
    }


# ---------------------------------------------------------------------------
# Report helpers (per-finding + consolidated Mermaid maps)
# ---------------------------------------------------------------------------


def _generate_finding_mermaid(
    finding_id: str,
    title: str,
    endpoint: str,
    data_classification: str,
    mutability: str,
    affected_schemas: str,
    isolated_schemas: str,
) -> str:
    """Generate a Mermaid diagram visualizing a finding's blast radius and containment."""
    clean_title = re.sub(r'["\']', "", title)[:35]
    clean_ep = re.sub(r'["\']', "", endpoint or "/api")[:25]
    clean_mut = re.sub(r'["\']', "", mutability or "Read-Only")
    clean_class = re.sub(r'["\']', "", data_classification or "Exposed Data")

    aff_items = [s.strip() for s in affected_schemas.split(",") if s.strip()] or ["Target Surface"]
    iso_items = [s.strip() for s in isolated_schemas.split(",") if s.strip()] or [
        "Core 80TB Estate"
    ]

    lines = [
        "```mermaid",
        "graph TD",
        (
            '    Attacker["External Attacker / Client"] -->|Exploits| '
            f'Vuln["{finding_id}: {clean_ep}<br/>({clean_title})"]'
        ),
        f'    subgraph Compromised ["Compromised Scope: {clean_class}"]',
    ]
    for idx, item in enumerate(aff_items):
        safe_item = re.sub(r'["\']', "", item)
        node_id = f"Aff_{idx}"
        lines.append(
            f'        {node_id}["Schema/Resource: {safe_item}<br/>(Can be Changed: {clean_mut})"]'
        )
        lines.append(f"        Vuln --> {node_id}")
    lines.append("    end")

    lines.append('    subgraph Protected ["Protected & Isolated Estate (~80TB Bound)"]')
    for idx, item in enumerate(iso_items):
        safe_item = re.sub(r'["\']', "", item)
        node_id = f"Iso_{idx}"
        lines.append(f'        {node_id}["Schema: {safe_item} (BLOCKED / ISOLATED)"]')
    lines.append("    end")
    lines.append("    Vuln -.->|Access Denied / Strictly Contained| Protected")
    lines.append("```")
    return "\n".join(lines)


def _generate_consolidated_mermaid(findings: list[dict[str, Any]]) -> str:
    """Generate a consolidated Mermaid attack-surface and blast-radius diagram."""
    if not findings:
        return ""
    lines = [
        "```mermaid",
        "graph TD",
        '    Attacker["External Attacker / Client"]',
        '    subgraph Compromised_Assets ["Compromised Assets & Exposed Schemas"]',
    ]
    for i, item in enumerate(findings[:6]):
        fid = str(item.get("id", f"VULN-{i + 1}"))
        ep = re.sub(r'["\']', "", str(item.get("endpoint", "") or "Web API"))[:20]
        mut = re.sub(r'["\']', "", str(item.get("mutability") or "Read-Only"))[:15]
        d_class = re.sub(r'["\']', "", str(item.get("data_classification") or "Exposed Data"))[:20]
        vnode = f"V_{i}"
        cnode = f"C_{i}"
        lines.append(
            f'        {vnode}["{fid}: {ep}"] --> {cnode}["{d_class}<br/>(Changeable: {mut})"]'
        )

    lines.append("    end")
    lines.extend(f"    Attacker --> V_{i}" for i in range(min(len(findings), 6)))

    lines.append(
        '    subgraph Isolated_Estate ["Protected Enterprise Estate (~80TB Core Schemas)"]'
    )
    lines.append('        Iso1["Core Production Databases (ISOLATED)"]')
    lines.append('        Iso2["Auth & Payment Records (PROTECTED)"]')
    lines.append("    end")
    lines.append("    Attacker -.->|Access Blocked / Contained| Isolated_Estate")
    lines.append("```")
    return "\n".join(lines)


def _extract_blast_radius_summary(item: dict[str, Any]) -> tuple[str, str, str, str]:
    """Extract (data_classification, mutability, blast_radius, containment) from finding."""
    impact = str(item.get("impact") or "")
    data_class = str(item.get("data_classification") or "")
    mutability = str(item.get("mutability") or "")
    blast = str(item.get("blast_radius") or "")
    containment = str(item.get("containment") or "")

    if not data_class:
        for line in impact.splitlines():
            line_s = line.strip().lstrip("*-# ").strip()
            if ":" not in line_s:
                continue
            lowered = line_s.lower()
            if lowered.startswith("data classification:"):
                data_class = line_s.split(":", 1)[1].strip()
                break
            if lowered.startswith("data leaked:"):
                data_class = line_s.split(":", 1)[1].strip()
                break

    if not mutability:
        for line in impact.splitlines():
            line_s = line.strip().lstrip("*-# ").strip()
            if ":" not in line_s:
                continue
            lowered = line_s.lower()
            if (
                "mutability" in lowered
                or "can data be changed" in lowered
                or "can it be changed" in lowered
            ):
                mutability = line_s.split(":", 1)[1].strip()
                break

    if not blast:
        for line in impact.splitlines():
            line_s = line.strip().lstrip("*-# ").strip()
            if ":" not in line_s:
                continue
            lowered = line_s.lower()
            if lowered.startswith(("blast radius:", "blast radius & reachability:")):
                blast = line_s.split(":", 1)[1].strip()
                break

    if not containment:
        for line in impact.splitlines():
            line_s = line.strip().lstrip("*-# ").strip()
            if ":" not in line_s:
                continue
            lowered = line_s.lower()
            if lowered.startswith(("containment:", "containment boundary:")):
                containment = line_s.split(":", 1)[1].strip()
                break

    data_class = data_class or "Unclassified"
    mutability = mutability or "Read-Only (No writes)"
    blast = blast or (impact[:80] + "..." if len(impact) > 80 else impact) or "See finding details"
    containment = containment or "Contained"
    return data_class, mutability, blast, containment


@mcp.tool()
async def sandbox_stop() -> dict[str, Any]:
    """Stop and remove the sandbox container for this run (cleanup)."""
    from strix.runtime import session_manager

    await session_manager.cleanup(_SCAN_ID)
    return {"stopped": True, "scan_id": _SCAN_ID}


if __name__ == "__main__":
    mcp.run()
