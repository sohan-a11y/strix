import asyncio
import atexit
import contextlib
import logging
import signal
import sys
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from strix.config import load_settings
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.agents import AgentCoordinator
from strix.core.runner import run_strix_scan
from strix.interface.dashboard import DashboardState, StrixDashboard
from strix.interface.tui.live_view import TuiLiveView
from strix.llm.provider_chain import add_provider_switch_listener
from strix.report.state import ReportState, set_global_report_state
from strix.runtime import session_manager
from strix.tools.todo.tools import snapshot_all_todos

from .utils import format_vulnerability_report, read_workspace_files


logger = logging.getLogger(__name__)

# Live dashboard refresh/poll cadence: the renderable redraws itself from
# DashboardState at this rate, and the graph/todo poller refreshes that state.
DASHBOARD_REFRESH_HZ = 4
GRAPH_POLL_SECONDS = 0.5


def _resolve_sandbox_image() -> str:
    image = load_settings().runtime.image
    if not image:
        raise RuntimeError(
            "strix_image is not configured. Set it in ~/.strix/cli-config.json.",
        )
    return image


def _dashboard_model(model: str | None) -> str:
    resolved = str(model or "").strip()
    if resolved:
        return resolved
    with contextlib.suppress(Exception):
        resolved = str(load_settings().llm.model or "").strip()
    return resolved or "unknown"


def _dashboard_targets(targets_info: list[dict[str, Any]]) -> list[str]:
    return [
        str(info.get("original") or "").strip()
        for info in targets_info or []
        if str(info.get("original") or "").strip()
    ]


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()

    start_text = Text()
    start_text.append("Penetration test initiated", style="bold #22c55e")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    results_text = Text()
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(f"strix_runs/{args.run_name}", style="#60a5fa")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append(
        "Live dashboard follows: agent activity, plan, findings, spend.",
        style="dim",
    )

    startup_panel = Panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n",
            results_text,
            note_text,
        ),
        title="[bold white]STRIX",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(startup_panel)
    console.print()

    scan_mode = getattr(args, "scan_mode", "deep")
    max_turns = getattr(args, "max_turns", DEFAULT_MAX_TURNS)

    scan_config: dict[str, Any] = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scan_mode": scan_mode,
        "non_interactive": bool(getattr(args, "non_interactive", False)),
        "local_sources": getattr(args, "local_sources", None) or [],
        "workspace_files": getattr(args, "workspace_files", None) or [],
        "scope_mode": getattr(args, "scope_mode", "auto"),
        "diff_base": getattr(args, "diff_base", None),
        "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
    }

    report_state = ReportState(args.run_name)
    report_state.hydrate_from_run_dir()
    report_state.set_scan_config(scan_config)
    report_state.save_run_data()

    def display_vulnerability(report: dict[str, Any], *, updated: bool = False) -> None:
        report_id = report.get("id", "unknown")

        vuln_text = format_vulnerability_report(report)

        suffix = " (updated)" if updated else ""
        vuln_panel = Panel(
            vuln_text,
            title=f"[bold red]{report_id.upper()}{suffix}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    def display_vulnerability_deleted(report: dict[str, Any]) -> None:
        report_id = str(report.get("id", "unknown"))
        deletion = report.get("deletion")
        deletion = deletion if isinstance(deletion, dict) else {}
        deleted_by = deletion.get("agent_name") or deletion.get("agent_id") or "agent"
        text = Text()
        text.append("Withdrawn: ", style="bold")
        text.append(f"{report.get('title', '')}\n\n")
        text.append(f"Deleted by {deleted_by}. ", style="dim")
        text.append(str(deletion.get("reason") or ""))
        console.print(
            Panel(
                text,
                title=f"[bold yellow]{report_id.upper()} (withdrawn)",
                title_align="left",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()

    report_state.vulnerability_found_callback = display_vulnerability
    report_state.vulnerability_updated_callback = lambda report: display_vulnerability(
        report, updated=True
    )
    report_state.vulnerability_deleted_callback = display_vulnerability_deleted

    def cleanup_on_exit() -> None:
        report_state.cleanup()

    def signal_handler(_signum: int, _frame: Any) -> None:
        report_state.cleanup(status="interrupted")
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_report_state(report_state)

    # -- live dashboard wiring ------------------------------------------------
    # OneBidirectional feed of everything already pushed by the engine:
    # graph/todo snapshots polled from the coordinator (its own instance is
    # handed to run_strix_scan below), SDK stream events folded through the
    # same TuiLiveView projection the TUI uses, startup phases and the MCP
    # roster arriving through their engine sinks.
    dashboard_state = DashboardState(
        run_name=args.run_name,
        targets=_dashboard_targets(args.targets_info),
        model=_dashboard_model(getattr(args, "llm", None)),
        max_turns=max_turns,
        max_budget_usd=getattr(args, "max_budget_usd", None),
    )
    dashboard = StrixDashboard(dashboard_state, report_state)
    live_view = TuiLiveView()
    coordinator = AgentCoordinator()
    live_view.set_user_instruction(str(scan_config.get("user_instructions") or ""))
    _error_noted_agents: set[str] = set()

    def on_provider_switched(from_label: str, to_label: str, reason: str) -> None:
        # The dashboard status line tracks phases through note_phase; the
        # switch also surfaces inline so it is visible between refreshes.
        dashboard_state.note_phase(f"llm provider → {to_label}")
        console.print(
            f"\n[bold yellow]LLM provider switch:[/] [white]{from_label}[/] is out of "
            f"quota ({reason}); continuing on [cyan]{to_label}[/]\n"
        )

    add_provider_switch_listener(on_provider_switched)

    run_dir = report_state.get_run_dir()
    if (run_dir / ".state" / "agents.json").exists():
        # Resuming: replay the prior run's recent SDK history so the activity
        # feed and per-agent cells do not start blank.
        live_view.hydrate_from_run_dir(run_dir)

    def on_scan_event(agent_id: str, event: Any) -> None:
        try:
            live_view.ingest_sdk_event(agent_id, event)
            dashboard_state.drain_live_view(live_view)
        except Exception:
            logger.debug("dashboard event absorption failed", exc_info=True)

    def on_mcp_status(roster: list[dict[str, Any]]) -> None:
        dashboard_state.note_mcp_roster(roster)

    async def poll_graph_and_todos() -> None:
        while True:
            try:
                parent_of, statuses, names, errors = await coordinator.graph_snapshot()
                dashboard_state.update_graph(parent_of, statuses, names, errors)
                dashboard_state.update_todos(snapshot_all_todos())
                for agent_id, status in statuses.items():
                    live_view.upsert_agent(
                        agent_id,
                        name=names.get(agent_id, agent_id),
                        parent_id=parent_of.get(agent_id),
                        status=str(status),
                        error_message=errors.get(agent_id),
                    )
                    error = errors.get(agent_id)
                    if status in {"failed", "crashed"} and error:
                        if agent_id not in _error_noted_agents:
                            _error_noted_agents.add(agent_id)
                            live_view.record_agent_error(agent_id, error)
                    else:
                        _error_noted_agents.discard(agent_id)
                live_view.flush_user_instruction()
                dashboard_state.drain_live_view(live_view)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("dashboard poll failed", exc_info=True)
            await asyncio.sleep(GRAPH_POLL_SECONDS)

    try:
        console.print()

        with Live(
            dashboard,
            console=console,
            refresh_per_second=DASHBOARD_REFRESH_HZ,
            transient=False,
        ):
            poll_task = asyncio.create_task(poll_graph_and_todos())
            try:
                logger.info(
                    "CLI launching scan: run_name=%s targets=%d interactive=%s",
                    args.run_name,
                    len(scan_config.get("targets") or []),
                    bool(getattr(args, "interactive", False)),
                )
                await run_strix_scan(
                    scan_config=scan_config,
                    scan_id=args.run_name,
                    image=_resolve_sandbox_image(),
                    local_sources=getattr(args, "local_sources", None) or [],
                    extra_files=read_workspace_files(getattr(args, "workspace_files", None)),
                    coordinator=coordinator,
                    interactive=bool(getattr(args, "interactive", False)),
                    max_budget_usd=getattr(args, "max_budget_usd", None),
                    max_turns=max_turns,
                    status_sink=dashboard_state.note_phase,
                    event_sink=on_scan_event,
                    mcp_status_sink=on_mcp_status,
                )
            finally:
                poll_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await poll_task
                with contextlib.suppress(Exception):
                    await session_manager.cleanup(args.run_name)

    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if report_state.final_scan_result:
        console.print()

        final_report_text = Text()
        final_report_text.append("Penetration test summary", style="bold #60a5fa")

        final_report_panel = Panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                report_state.final_scan_result,
            ),
            title="[bold white]STRIX",
            title_align="left",
            border_style="#60a5fa",
            padding=(1, 2),
        )

        console.print(final_report_panel)
        console.print()
