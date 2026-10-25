"""Headless dashboard render/state plus the cross-agent todo snapshot."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from rich.console import Console

from strix.interface.dashboard import (
    DashboardState,
    StrixDashboard,
    _clean_text,
    _format_cost,
    _format_tokens,
    _tree_rows,
)
from strix.tools.todo.tools import hydrate_todos_from_disk, snapshot_all_todos


if TYPE_CHECKING:
    from pathlib import Path


def render(dashboard: StrixDashboard, *, width: int = 100, height: int = 40) -> str:
    console = Console(
        file=io.StringIO(),
        width=width,
        height=height,
        legacy_windows=False,
        force_terminal=False,
    )
    with console.capture() as capture:
        console.print(dashboard)
    return capture.get()


def state(**overrides: Any) -> DashboardState:
    defaults: dict[str, Any] = {
        "run_name": "run-x",
        "targets": ["https://example.com"],
        "model": "test/model",
        "max_turns": 50,
        "max_budget_usd": 10.0,
    }
    defaults.update(overrides)
    return DashboardState(**defaults)


def tool_event(
    agent_id: str,
    *,
    event_id: str = "tool_1",
    version: int = 0,
    status: str = "running",
    tool_name: str = "curl",
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": event_id,
        "type": "tool",
        "agent_id": agent_id,
        "timestamp": "2026-10-25T09:00:00+00:00",
        "version": version,
        "data": {"tool_name": tool_name, "args": args or {}, "status": status},
    }


def chat_event(
    agent_id: str,
    content: str,
    *,
    event_id: str = "chat_1",
    version: int = 0,
    streaming: bool | None = None,
) -> dict[str, Any]:
    metadata = None if streaming is None else {"streaming": streaming}
    return {
        "id": event_id,
        "type": "chat",
        "agent_id": agent_id,
        "timestamp": "2026-10-25T09:00:05+00:00",
        "version": version,
        "data": {"role": "assistant", "content": content, "metadata": metadata},
    }


def usage_report(requests: int = 0, tokens: int = 0, cost: float = 0.0) -> Any:
    return SimpleNamespace(
        vulnerability_reports=[],
        final_scan_result=None,
        get_total_llm_usage=lambda: {
            "agents": [{"agent_id": "r1", "requests": requests, "total_tokens": tokens}],
            "requests": requests,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost": cost,
        },
    )


# --------------------------------------------------------------------------- #
# snapshot_all_todos
# --------------------------------------------------------------------------- #


def test_snapshot_all_todos_returns_sorted_status_title_pairs(
    tmp_path: Path,
) -> None:
    store = tmp_path / ".state"
    store.mkdir()
    todos = {
        "root": {
            "a": {
                "title": "Probe admin",
                "status": "in_progress",
                "priority": "high",
                "created_at": "2026-01-02T00:00:00+00:00",
            },
            "b": {
                "title": "Enumerate subdomains",
                "status": "done",
                "priority": "normal",
                "created_at": "2026-01-01T00:00:00+00:00",
            },
            "c": {
                "title": "Exploit IDOR",
                "status": "pending",
                "priority": "critical",
                "created_at": "2026-01-03T00:00:00+00:00",
            },
        },
        "child": {},
    }
    (store / "todos.json").write_text(json.dumps(todos), encoding="utf-8")
    hydrate_todos_from_disk(store)
    try:
        snapshot = snapshot_all_todos()

        assert snapshot["root"] == [
            ("done", "Enumerate subdomains"),
            ("in_progress", "Probe admin"),
            ("pending", "Exploit IDOR"),
        ]
        # Agents with no todos are omitted entirely.
        assert "child" not in snapshot
        assert snapshot_all_todos() == snapshot
    finally:
        hydrate_todos_from_disk(tmp_path / "no-such-state")


def test_snapshot_all_todos_is_empty_without_a_store(tmp_path: Path) -> None:
    hydrate_todos_from_disk(tmp_path / "no-such-state")
    assert snapshot_all_todos() == {}


# --------------------------------------------------------------------------- #
# render
# --------------------------------------------------------------------------- #


def test_empty_state_renders_placeholders_without_agents() -> None:
    text = render(StrixDashboard(state(), None))

    assert "waiting for the first agent to start" in text
    assert "○ sandbox" in text and "○ agents" in text
    assert "FINDINGS none yet" in text


def test_pipeline_stages_advance_and_never_regress() -> None:
    dash_state = state()
    dash = StrixDashboard(dash_state, None)

    dash_state.note_phase("Starting sandbox container")
    text = render(dash)
    assert "● sandbox" in text

    dash_state.note_phase("Setting up the proxy")
    text = render(dash)
    assert "✓ sandbox" in text
    assert "● proxy" in text

    dash_state.note_phase("Waiting for the first model response")
    text = render(dash)
    assert "✓ proxy" in text
    # The mcp stage stays hidden until a connection is configured.
    assert " mcp " not in text

    dash_state.note_mcp_roster(
        [
            {
                "name": "cyberchef",
                "provider": "stdio",
                "tool_count": 1,
                "dead": False,
                "state": "catalog_ready",
            }
        ]
    )
    dash_state.note_phase("MCP: configured 1 connection(s); connecting and listing tools")
    text = render(dash)
    assert "● mcp" in text


def test_agents_block_shows_usage_and_steps_left() -> None:
    dash_state = state()
    dash_state.update_graph({"r1": None}, {"r1": "running"}, {"r1": "Root Agent"}, {})
    reports = usage_report(requests=8, tokens=4_200, cost=0.02)

    text = render(StrixDashboard(dash_state, reports))

    assert "42/50" in text  # 8 requests of a 50-turn cap used
    assert "steps left/limit" in text
    assert "4.2K" in text
    assert "$0.02" in text


def test_subscription_runs_show_a_zero_cost() -> None:
    dash_state = state()
    dash_state.update_graph({"r1": None}, {"r1": "running"}, {"r1": "Root Agent"}, {})

    text = render(StrixDashboard(dash_state, SimpleNamespace(vulnerability_reports=[])))

    assert "$0.00" in text


def test_findings_render_severity_chips_and_the_latest_title() -> None:
    reports = SimpleNamespace(
        vulnerability_reports=[
            {
                "id": "vuln-0001",
                "severity": "critical",
                "title": "SQL injection in /admin",
            },
            {
                "id": "vuln-0002",
                "severity": "low",
                "title": "Verbose error page",
            },
        ],
    )

    text = render(StrixDashboard(state(), reports))

    assert "FINDINGS" in text
    assert "CRITICAL 1" in text
    assert "LOW 1" in text
    assert "latest Verbose error page" in text


def test_plan_block_lists_the_root_plan_progress() -> None:
    dash_state = state()
    dash_state.update_graph(
        {"r1": None, "s1": "r1"},
        {"r1": "running", "s1": "running"},
        {"r1": "Root Agent", "s1": "sub"},
        {},
    )
    dash_state.update_todos(
        {"r1": [("done", "Recon the target"), ("pending", "Exploit the admin panel")]}
    )

    text = render(StrixDashboard(dash_state, None))

    assert "PLAN 1/2" in text
    assert "Recon the target" in text
    assert "Exploit the admin panel" in text


def test_crashed_agents_show_their_error_row() -> None:
    dash_state = state()
    dash_state.update_graph(
        {"x": None}, {"x": "crashed"}, {"x": "sub-agent"}, {"x": "it died: connection dropped"}
    )

    text = render(StrixDashboard(dash_state, None))

    assert "↳" in text
    assert "it died: connection dropped" in text


def test_tree_rows_walk_depth_first_with_connectors() -> None:
    rows = _tree_rows({"r1": None, "c1": "r1", "c2": "r1", "g1": "c1"})

    assert [agent_id for _depth, agent_id, _connector in rows] == [
        "r1",
        "c1",
        "g1",
        "c2",
    ]
    connectors = {agent_id: connector for _depth, agent_id, connector in rows}
    assert connectors["c1"].startswith("├─")
    assert connectors["c2"].startswith("└─")
    assert connectors["g1"].startswith("│   └─")


def test_formatters() -> None:
    assert _format_cost(0) == "$0.00"
    assert _format_cost(0.5) == "$0.5000"
    assert _format_cost(2.5) == "$2.50"
    assert _format_tokens(999) == "999"
    assert _format_tokens(1_500) == "1.5K"
    assert _format_tokens(2_500_000) == "2.5M"
    assert _clean_text("a\n b\t  c") == "a b c"


def test_rerenders_at_narrow_and_short_viewports() -> None:
    dash_state = state()
    dash_state.update_graph(
        {"r1": None, "s1": "r1"},
        {"r1": "running", "s1": "running"},
        {"r1": "Root Agent", "s1": "sub"},
        {},
    )
    dash_state.update_todos(
        {"r1": [("done", "Recon"), ("pending", "Exploit"), ("pending", "Report")]}
    )
    dash_state.absorb_event(tool_event("r1", args={"url": "https://example.com/admin"}))
    dash = StrixDashboard(dash_state, usage_report(requests=3, tokens=900))

    wide = render(dash)
    narrow = render(dash, width=44, height=10)
    tall = render(dash, height=120)

    assert wide
    assert narrow
    assert tall
    # A short viewport drops the activity feed rather than scrolling offscreen.
    assert "ACTIVITY" not in narrow
    assert "ACTIVITY" in tall


# --------------------------------------------------------------------------- #
# event absorption
# --------------------------------------------------------------------------- #


def test_absorb_event_dedupes_bumps_and_holds_streaming_chat() -> None:
    dash_state = state()
    dash_state.update_graph({"r1": None}, {"r1": "running"}, {"r1": "Root Agent"}, {})

    dash_state.absorb_event(tool_event("r1", args={"url": "https://example.com/admin"}))
    dash_state.absorb_event(
        tool_event(
            "r1",
            args={"url": "https://example.com/admin"},
            version=1,
            status="completed",
        )
    )
    dash_state.absorb_event(chat_event("r1", "partial ", streaming=True))
    dash_state.absorb_event(
        chat_event("r1", "The enumeration finished.", version=1, streaming=False)
    )

    snap = dash_state.snapshot_unlocked()
    subjects = [entry["subject"] for entry in snap["feed"]]
    assert subjects.count("curl https://example.com/admin") == 1
    assert "The enumeration finished." in subjects
    assert not any(subject == "partial" for subject in subjects)


def test_drain_absorbs_new_events_and_recent_bumps() -> None:
    dash_state = state()
    dash_state.update_graph({"r1": None}, {"r1": "running"}, {"r1": "Root Agent"}, {})
    view = SimpleNamespace()
    view.events = []

    assert dash_state.drain_live_view(view) == 0

    event = tool_event("r1", args={"url": "https://example.com/admin"})
    view.events = [event]
    assert dash_state.drain_live_view(view) == 1
    snap = dash_state.snapshot_unlocked()
    assert snap["now_cells"]["r1"] == "curl https://example.com/admin"
    assert len(snap["feed"]) == 1

    event["version"] = 1
    dash_state.drain_live_view(view)
    snap = dash_state.snapshot_unlocked()
    assert len(snap["feed"]) == 1  # bumps re-derive, they do not duplicate


def test_root_finish_scan_marks_the_reporting_stage() -> None:
    dash_state = state()
    dash_state.update_graph({"r1": None}, {"r1": "running"}, {"r1": "Root Agent"}, {})

    dash_state.absorb_event(
        tool_event(
            "r1",
            event_id="tool_9",
            tool_name="finish_scan",
            status="completed",
        )
    )

    assert dash_state.snapshot_unlocked()["root_finishing"] is True
    text = render(StrixDashboard(dash_state, None))
    assert "✓ report" in text


def test_failed_finish_scan_does_not_mark_the_report_ready() -> None:
    dash_state = state()
    dash_state.update_graph({"r1": None}, {"r1": "running"}, {"r1": "Root Agent"}, {})

    dash_state.absorb_event(
        tool_event(
            "r1",
            event_id="tool_9",
            tool_name="finish_scan",
            status="failed",
        )
    )

    assert dash_state.snapshot_unlocked()["root_finishing"] is False
