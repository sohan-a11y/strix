"""Headless live dashboard: what every agent is doing, and what is left.

One Rich renderable composed from the progress plumbing that already exists:

- the agent graph (``AgentCoordinator.graph_snapshot``), pushed by an async
  poller started by the caller;
- the SDK stream events through the same ``TuiLiveView`` projection the TUI
  uses, folded into per-agent "now" cells and a rolling activity feed;
- the run record's usage ledger (requests, tokens, cost) and filed findings;
- the agents' own plan, taken from the coordinator's todo store;
- coarse startup phases pushed through ``status_sink``.

Missing data renders placeholders, narrow terminals truncate, and threading
races are contained behind one lock. Only ``rich`` is required.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from rich.text import Text


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


_GREEN = "#22c55e"
_LIME = "#4ade80"
_YELLOW = "#eab308"
_AMBER = "#fbbf24"
_RED = "#dc2626"
_BLUE = "#60a5fa"
_CYAN = "#38bdf8"
_GRAY = "#6b7280"
_BRIGHT_GRAY = "#9ca3af"

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_STYLE = {
    "critical": _RED,
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#0284c7",
}
_STATUS_GLYPHS: dict[str, tuple[str, str]] = {
    "running": ("●", _GREEN),
    "waiting": ("◐", _YELLOW),
    "completed": ("✓", _LIME),
    "stopped": ("■", _GRAY),
    "crashed": ("✗", _RED),
    "failed": ("✗", _RED),
    "budget_paused": ("‖", _YELLOW),
}
_TODO_GLYPHS: dict[str, tuple[str, str]] = {
    "pending": ("○", _BRIGHT_GRAY),
    "in_progress": ("◐", _AMBER),
    "done": ("✓", _LIME),
}
_SPINNER_FRAMES: tuple[str, ...] = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


def spinner_frame() -> str:
    """Current braille frame, advanced continuously so any tick looks live."""
    return _SPINNER_FRAMES[int(time.monotonic() * 3.5) % len(_SPINNER_FRAMES)]


def _clean_text(value: Any) -> str:
    """Flatten event text into one displayable line without control chars."""
    return " ".join(str(value or " ").split())


def _json_dict(value: object) -> dict[str, Any]:
    """Normalize a JSON-ish value into a mapping fit for field access.

    Values come from SDK events and report state, so anything structurally
    unexpected (a lost dict, a list instead of a map) becomes an empty
    mapping instead of a crash on ``.get``.
    """
    if not isinstance(value, dict):
        return {}
    return cast("dict[str, Any]", value)


def _clip(value: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    return value[: max(0, width - 1)] + "…"


def _format_cost(cost: float) -> str:
    if cost == 0:
        return "$0.00"
    if cost >= 1:
        return f"${cost:,.2f}"
    return f"${cost:.4f}"


def _format_tokens(count: int) -> str:
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)


def _format_steps(requests: int, max_turns: int | None) -> str:
    """``left/limit`` while a cap exists — the steps each agent has left."""
    if max_turns and max_turns > 0:
        return f"{max(0, max_turns - requests)}/{max_turns}"
    return str(requests)


def _elapsed(started_monotonic: float) -> str:
    seconds = max(0, int(time.monotonic() - started_monotonic))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _timestamp_label(iso: Any) -> str:
    """Render an event timestamp as ``HH:MM:SS``; empty string when unusable."""
    if not isinstance(iso, str) or not iso.strip():
        return ""
    try:
        moment = datetime.fromisoformat(iso.strip().replace("Z", "+00:00"))
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%H:%M:%S")


def _tree_rows(parents: dict[str, str | None]) -> list[tuple[int, str, str]]:
    """DFS tree rows as ``(depth, agent_id, connector_prefix)`` for the table."""
    children: dict[str, list[str]] = {}
    roots: list[str] = []
    for agent_id, parent in parents.items():
        if not parent or parent not in parents:
            roots.append(agent_id)
        else:
            children.setdefault(parent, []).append(agent_id)
    rows: list[tuple[int, str, str]] = []

    def walk(agent_id: str, depth: int, inherited: str, row_prefix: str) -> None:
        rows.append((depth, agent_id, row_prefix))
        kids = children.get(agent_id, [])
        for index, kid in enumerate(kids):
            last = index == len(kids) - 1
            tee = "└─ " if last else "├─ "
            walk(
                kid,
                depth + 1,
                inherited + ("    " if last else "│   "),
                inherited + tee,
            )

    for root in roots:
        walk(root, 0, "", "")
    return rows


class DashboardState:
    """Thread-safe accumulator of everything the live render reads."""

    def __init__(
        self,
        *,
        run_name: str,
        targets: list[str],
        model: str,
        max_turns: int | None,
        max_budget_usd: float | None,
    ) -> None:
        self._lock = threading.Lock()
        self.run_name = run_name
        self.targets = targets
        self.model = str(model or "unknown").strip() or "unknown"
        self.max_turns = max_turns
        self.max_budget_usd = max_budget_usd
        self.started_monotonic = time.monotonic()

        self.phase = "Starting up"
        # Lowercased history of every phase pushed through note_phase: the
        # pipeline row derives its completed/in-progress stages from it and
        # never regresses even when the phase string does not name a stage.
        self.phases_seen: set[str] = set()
        self.parents: dict[str, str | None] = {}
        self.statuses: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.errors: dict[str, str] = {}
        self.mcp_roster: list[dict[str, Any]] = []

        self.root_ids: list[str] = []
        self.root_finishing = False
        self.now_cells: dict[str, Text] = {}
        self.feed: list[dict[str, str]] = []
        self._feed_keys: set[str] = set()
        self._consumed = 0
        self.todos: dict[str, list[tuple[str, str]]] = {}

    # -- phase, graph, todo sinks -----------------------------------------

    def note_phase(self, phase: str) -> None:
        if not phase:
            return
        lowered = phase.lower()
        tokens = {"sandbox", "proxy", "mcp", "model response"}
        with self._lock:
            self.phase = phase
            self.phases_seen.update(token for token in tokens if token in lowered)

    def note_mcp_roster(self, roster: list[dict[str, Any]]) -> None:
        with self._lock:
            self.mcp_roster = list(roster or [])

    def update_graph(
        self,
        parents: Mapping[str, str | None],
        statuses: Mapping[str, str],
        names: Mapping[str, str],
        errors: Mapping[str, str],
    ) -> None:
        roots = [agent_id for agent_id, parent in parents.items() if not parent]
        with self._lock:
            self.parents = dict(parents or {})
            self.statuses = dict(statuses or {})
            self.names = dict(names or {})
            self.errors = dict(errors or {})
            self.root_ids = roots

    def update_todos(self, todos: dict[str, list[tuple[str, str]]]) -> None:
        with self._lock:
            self.todos = {agent: list(items) for agent, items in (todos or {}).items()}

    def snapshot_unlocked(self) -> dict[str, Any]:
        with self._lock:
            return {
                "phase": self.phase,
                "parents": dict(self.parents),
                "statuses": dict(self.statuses),
                "names": dict(self.names),
                "errors": dict(self.errors),
                "root_finishing": self.root_finishing,
                "feed": list(self.feed),
                "phases_seen": tuple(self.phases_seen),
                "now_cells": {key: value.plain for key, value in self.now_cells.items()},
                "todos": {key: list(value) for key, value in self.todos.items()},
                "mcp_roster": list(self.mcp_roster),
            }

    # -- event absorption -------------------------------------------------

    def drain_live_view(self, view: Any) -> int:
        """Fold a live view's new events in, plus its last few for bump updates.

        ``TuiLiveView`` mutates events in place (version bumps) instead of
        appending duplicates, and tool outputs arrive right after their calls,
        so re-absorbing the last few events already drained catches those
        updates. Returns how many events were re-projected.
        """
        events = list(getattr(view, "events", None) or [])
        if not events:
            return 0
        with self._lock:
            consumed = self._consumed
            start = max(0, min(consumed - 3, len(events) - 3))
            self._consumed = len(events)
        for event in events[start:]:
            self.absorb_event(event)
        return len(events) - start

    def absorb_event(self, event: dict[str, Any]) -> None:
        """Fold one projected event (TuiLiveView shape) into the render state."""
        event_type = event.get("type")
        agent_id = str(event.get("agent_id") or "")
        data = _json_dict(event.get("data"))
        key = str(event.get("id") or "")
        at = _timestamp_label(event.get("timestamp"))

        with self._lock:
            is_root = agent_id in self.root_ids
            if event_type == "tool":
                tool_name = _clean_text(data.get("tool_name") or "tool")
                if data.get("mcp_connection"):
                    tool_name = f"{data['mcp_connection']}/{data.get('mcp_tool') or 'tool'}"
                preview = _clean_text(self._tool_arg_preview(data.get("args") or {}))
                status = str(data.get("status") or "running")
                entry = f"{tool_name} {preview}".strip()
                self.now_cells[agent_id] = Text(entry if entry else tool_name)
                if is_root and tool_name == "finish_scan":
                    self.root_finishing = status != "failed"
                self._push_feed(key, agent_id, "tool", entry, at)
            elif event_type == "chat":
                role = str(data.get("role") or "assistant")
                content = _clean_text(data.get("content") or "")
                if not content:
                    return
                self.now_cells.setdefault(agent_id, Text("planning next steps"))
                metadata = _json_dict(data.get("metadata"))
                if metadata.get("streaming"):
                    # Deltas re-write the same event as it streams in; hold the
                    # feed line until the final message lands so the activity
                    # feed does not flood with one line per token.
                    return
                self._push_feed(key, agent_id, role, content, at)

    def _push_feed(self, key: str, agent_id: str, kind: str, subject: str, at: str) -> None:
        """Append a deduped, capped activity line (call under the state lock)."""
        if key in self._feed_keys or not subject:
            return
        self._feed_keys.add(key)
        self.feed.append(
            {"key": key, "agent_id": agent_id, "kind": kind, "subject": subject[:160], "at": at}
        )
        if len(self.feed) > 12:
            dropped = self.feed[: len(self.feed) - 12]
            for entry in dropped:
                self._feed_keys.discard(entry["key"])
            self.feed = self.feed[-12:]
        if len(self._feed_keys) > 512:
            self._feed_keys = {entry["key"] for entry in self.feed}

    @staticmethod
    def _tool_arg_preview(args: Any) -> str:
        """The most informative short scalar values from a tool call."""
        arg_map = _json_dict(args)
        if not arg_map:
            return ""
        picked: list[str] = []
        for key in (
            "target",
            "url",
            "path",
            "source",
            "query",
            "command",
            "name",
            "goal",
            "description",
            "todo_ids",
            "agent_ids",
            "skills",
            "message",
            "collection_uid",
        ):
            value = arg_map.get(key)
            if isinstance(value, str) and value.strip():
                picked.append(_clip(_clean_text(value), 60))
            elif isinstance(value, list) and value:
                # pyright narrows this to list[Unknown] while mypy says
                # list[Any]; the cast reconciles both without redundancy.
                sample = cast("Sequence[Any]", value)[:2]
                picked.append(", ".join(str(item) for item in sample)[:60])
            if len(picked) >= 2:
                break
        if not picked:
            for value in arg_map.values():
                if isinstance(value, str) and value.strip():
                    picked.append(_clip(_clean_text(value), 60))
                    break
        return " ".join(picked)


class StrixDashboard:
    """Rich renderable showing the whole live view; refreshed every tick."""

    def __init__(self, state: DashboardState, report_state: Any) -> None:
        self.state = state
        self.report_state = report_state

    def __rich_console__(self, console: Any, options: Any) -> Any:
        width = int(options.max_width or 80)
        # `print` leaves `height` unset and shows the real viewport through
        # `max_height`, so read the console height from there.
        height = int(options.height or options.max_height or 48)
        yield from self._render(width, height)

    # -- read-only helpers -------------------------------------------------

    def _snapshot(self) -> dict[str, Any]:
        return self.state.snapshot_unlocked()

    def _root_id(self) -> str | None:
        parents = dict(self.state.snapshot_unlocked()["parents"])
        for agent_id, parent in parents.items():
            if not parent:
                return str(agent_id)
        return None

    def _agent_usage(self) -> dict[str, dict[str, int]]:
        if not self.report_state:
            return {}
        try:
            usage_record = self.report_state.get_total_llm_usage()
        except Exception:
            return {}
        result: dict[str, dict[str, int]] = {}
        empty_agents: list[Any] = []
        for raw_entry in usage_record.get("agents") or empty_agents:
            entry = _json_dict(raw_entry)
            if entry.get("agent_id"):
                try:
                    result[str(entry["agent_id"])] = {
                        "requests": int(entry.get("requests") or 0),
                        "total_tokens": int(entry.get("total_tokens") or 0),
                    }
                except (TypeError, ValueError):
                    continue
        return result

    def _usage_totals(self) -> dict[str, Any]:
        if not self.report_state:
            return {}
        try:
            totals: dict[str, Any] = dict(self.report_state.get_total_llm_usage() or {})
        except Exception:
            return {}
        return totals

    def _active_count(self, snap: dict[str, Any]) -> int:
        return sum(1 for status in snap["statuses"].values() if status == "running")

    def _all_agents_terminal(self, snap: dict[str, Any]) -> bool:
        statuses = list(snap["statuses"].values())
        return bool(statuses) and all(
            status in ("completed", "stopped", "failed", "crashed") for status in statuses
        )

    def _subscription_run(self) -> bool:
        if self.report_state is None:
            return False
        try:
            from strix.interface.utils import is_subscription_run

            return bool(is_subscription_run(self.report_state))
        except Exception:
            return False

    # -- sections -----------------------------------------------------------

    def _pipeline(self, snap: dict[str, Any]) -> Text:
        """One row of tracked stages: sandbox → proxy → [mcp] → agents → report.

        Stage state is derived from the phase history plus the agent graph, so
        a completed stage keeps its checkmark even when the current phase
        string names something else.
        """
        current = str(snap["phase"]).lower()
        seen = tuple(snap["phases_seen"])
        statuses_exist = bool(snap["statuses"])
        mcp_configured = bool(snap["mcp_roster"]) or any("mcp" in text for text in seen)
        active = self._active_count(snap)

        def seen_any(*tokens: str) -> bool:
            return any(token in text for text in seen for token in tokens)

        line = Text()

        def emit(stage: str, glyph: str, style: str) -> None:
            if line.plain:
                line.append("  ─  ", style=f"bold {_GRAY}")
            line.append(f"{glyph} ", style=style)
            if glyph == "✓":
                line.append(stage, style=f"bold {_GRAY}")
            elif glyph == "●":
                line.append(stage, style=f"bold {style}")
            else:
                line.append(stage, style=f"dim {_GRAY}")

        sandbox_active = any(token in current for token in ("sandbox", "workspace", "container"))
        if statuses_exist or seen_any("proxy", "mcp", "model response"):
            emit("sandbox", "✓", _GRAY)
        elif sandbox_active:
            emit("sandbox", "●", _GREEN)
        else:
            emit("sandbox", "○", _GRAY)

        if statuses_exist or seen_any("mcp", "model response"):
            emit("proxy", "✓", _GRAY)
        elif "proxy" in current:
            emit("proxy", "●", _GREEN)
        else:
            emit("proxy", "○", _GRAY)

        if mcp_configured:
            if statuses_exist:
                emit("mcp", "✓", _GRAY)
            elif "mcp" in current:
                emit("mcp", "●", _GREEN)
            else:
                emit("mcp", "○", _GRAY)

        if active:
            emit("agents", "●", _GREEN)
        elif statuses_exist:
            emit("agents", "◐", _AMBER)
        else:
            emit("agents", "○", _GRAY)

        finishing = bool(
            self.report_state is not None and getattr(self.report_state, "final_scan_result", None)
        )
        if finishing or snap["root_finishing"] or self._all_agents_terminal(snap):
            emit("report", "✓", _GRAY)
        elif self._findings_exist() or (statuses_exist and active == 0):
            emit("report", "◐", _AMBER)
        else:
            emit("report", "○", _GRAY)
        return line

    def _findings_exist(self) -> bool:
        return bool(getattr(self.report_state, "vulnerability_reports", ()) or ())

    def _agents_header(self, snap: dict[str, Any]) -> Text:
        active = self._active_count(snap)
        total = len(snap["statuses"])
        head = Text("  ")
        head.append("AGENTS ", style=f"bold {_GRAY}")
        head.append(f"{active} active", style=f"bold {_GREEN if active else _GRAY}")
        head.append(f"  ·  {total} total", style=f"dim {_GRAY}")
        if self.state.max_turns:
            head.append("  ·  steps left/limit", style=f"dim {_GRAY}")
        return head

    def _agents_block(self, width: int, snap: dict[str, Any]) -> list[Text]:
        usage_agents = self._agent_usage()
        if not snap["statuses"]:
            return [
                Text(
                    "  waiting for the first agent to start…",
                    style=f"dim italic {_GRAY}",
                )
            ]

        rows = _tree_rows(snap["parents"])
        if not rows:
            rows = [(0, agent_id, "") for agent_id in snap["statuses"]]
        name_width = max(
            (len(_clip(snap["names"].get(agent_id, agent_id), 24)) for _d, agent_id, _p in rows),
            default=8,
        )
        name_width = min(name_width, 24)
        now_width = max(min(width - (name_width + 20), 42), 14)
        lines: list[Text] = []

        for _depth, agent_id, connector in rows:
            status = snap["statuses"].get(agent_id, "running")
            glyph, style = _STATUS_GLYPHS.get(status, ("•", _GRAY))
            usage = usage_agents.get(agent_id, {})
            requests = int(usage.get("requests") or 0)
            tokens = int(usage.get("total_tokens") or 0)
            now = str(snap["now_cells"].get(agent_id, ""))

            if status == "running" and not now:
                now = "warming up"
            elif status == "waiting" and not now:
                now = "waiting on coordinator"
            elif status in ("completed", "stopped") and not now:
                now = "finished"

            row = Text("  ")
            row.append(f"{connector or '  '}", style=f"bold {_GRAY}")
            row.append(f"{glyph} ", style=style)
            name = _clip(snap["names"].get(agent_id, agent_id), name_width)
            row.append(name, style="bold white")
            row.append(" " * (name_width - len(name) + 2))
            now_clipped = _clip(now, now_width)
            row.append(now_clipped, style=f"dim {_GRAY}")
            row.append(" " * max(now_width - len(now_clipped), 1) + "  ")
            steps = _format_steps(requests, self.state.max_turns)
            row.append(f"{steps}", style=f"bold {style}" if status == "running" else f"{_GRAY}")
            row.append("   ")
            line_tokens = _clip(_format_tokens(tokens), 7)
            pad = max(0, 7 - len(line_tokens))
            row.append(" " * pad)
            row.append(line_tokens, style=_GRAY)
            lines.append(row)

            error = snap["errors"].get(agent_id)
            if error and status in ("crashed", "failed"):
                err_row = Text("  ")
                err_row.append(" " * (len(connector) + 2), style=f"bold {_GRAY}")
                err_row.append("↳ ", style=f"bold {_YELLOW}")
                err_row.append(_clip(_clean_text(error), max(width - 12, 30)), style=_YELLOW)
                lines.append(err_row)
        return lines

    def _plan_block(self, snap: dict[str, Any]) -> list[Text]:
        root_id = self._root_id()
        if not root_id:
            return []
        items = list(snap["todos"].get(root_id, []))
        if not items:
            return []
        counts = {"pending": 0, "in_progress": 0, "done": 0}
        for status, _label in items:
            counts[status] = counts.get(status, 0) + 1
        total = len(items)
        done = counts.get("done", 0)
        lines: list[Text] = []
        line = Text("  ")
        line.append("PLAN ", style=f"bold {_GRAY}")
        line.append(f"{done}/{total}", style=f"bold {_GREEN if done == total else 'white'}")
        line.append(" done", style=f"dim {_GRAY}")
        if counts.get("in_progress"):
            line.append(f"  ·  {counts['in_progress']} in progress", style=f"dim {_AMBER}")
        line.append(f"  ·  {counts.get('pending', 0)} remaining", style=f"dim {_GRAY}")
        lines.append(line)
        for status, label in items[:5]:
            glyph, style = _TODO_GLYPHS.get(status, ("○", _BRIGHT_GRAY))
            row = Text("     ")
            row.append(f"{glyph} ", style=style)
            row.append(
                _clip(_clean_text(label), 62),
                style="white" if status == "in_progress" else f"dim {_GRAY}",
            )
            lines.append(row)
        if total > 5:
            lines.append(Text(f"     … {total - 5} more", style=f"dim {_GRAY}"))
        return lines

    def _findings_line(self) -> Text:
        line = Text("  ")
        line.append("FINDINGS ", style=f"bold {_GRAY}")
        reports: list[Any] = list(getattr(self.report_state, "vulnerability_reports", []) or [])
        if not reports:
            line.append("none yet", style=f"dim italic {_GRAY}")
            return line
        severity_counts = dict.fromkeys(_SEVERITY_ORDER, 0)
        for report in reports:
            finding = _json_dict(report)
            severity = str(finding.get("severity") or "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        first = True
        for severity in _SEVERITY_ORDER:
            count = severity_counts[severity]
            if not count:
                continue
            if not first:
                line.append(" · ", style=_GRAY)
            first = False
            line.append(f"{severity.upper()} {count}", style=f"bold {_SEVERITY_STYLE[severity]}")
        latest = _json_dict(reports[-1])
        title = _clean_text(latest.get("title") or "")
        if title:
            line.append("   · latest ", style=f"dim {_GRAY}")
            line.append(_clip(title, 56), style="italic white")
        return line

    def _budget_line(self) -> Text:
        totals = self._usage_totals()
        max_turns = self.state.max_turns
        max_budget = self.state.max_budget_usd
        subtitle = Text("  ")
        subtitle.append("USAGE ", style=f"bold {_GRAY}")
        subtitle.append(
            f"{_format_tokens(int(totals.get('input_tokens') or 0))} in"
            f" · {_format_tokens(int(totals.get('output_tokens') or 0))} out"
            f" · {int(totals.get('requests') or 0)} calls",
            style="bold white",
        )
        subscription = self._subscription_run()
        subtitle.append("   COST ", style=f"bold {_GRAY}")
        if subscription:
            subtitle.append("$0.00", style=f"bold {_GREEN}")
            subtitle.append(" (subscription)", style=f"dim {_GRAY}")
        else:
            cost = float(totals.get("cost") or 0.0)
            subtitle.append(_format_cost(cost), style=f"bold {_AMBER}")
            if max_budget:
                subtitle.append(f" / ${max_budget:g}", style=f"dim {_GRAY}")
        if max_turns:
            subtitle.append("   TURNS ", style=f"bold {_GRAY}")
            subtitle.append(f"{max_turns} cap per agent", style=f"dim {_GRAY}")
        return subtitle

    def _feed_block(self, width: int, snap: dict[str, Any]) -> list[Text]:
        lines: list[Text] = []
        for item in reversed(snap["feed"][-5:]):
            agent_name = snap["names"].get(item.get("agent_id", ""), "?")
            subject = _clip(str(item.get("subject", "")), max(width - 34, 20))
            line = Text("  ")
            line.append(f"{item.get('at') or '  :  '} ", style=f"dim {_GRAY}")
            line.append(f"{_clip(agent_name, 16):16}", style=f"bold {_CYAN}")
            line.append(f"  {subject}", style=f"dim {_GRAY}")
            lines.append(line)
        return lines

    # -- composition -------------------------------------------------------

    def _render(self, width: int, height: int) -> list[Text]:
        """Assemble every section, then fit the activity feed to the viewport."""
        snap = self._snapshot()
        phase = str(snap["phase"])
        targets = list(self.state.targets)

        blocks: list[Text] = []
        blocks.extend(self._header_lines(width, targets))
        blocks.append(self._divider(width))
        blocks.append(Text("  "))

        pipeline = self._pipeline(snap)
        blocks.append(pipeline)
        if not snap["statuses"]:
            blocks.append(Text(f"    {phase}…", style=f"dim italic {_GRAY}"))

        blocks.append(Text(""))
        blocks.append(self._agents_header(snap))
        blocks.extend(self._agents_block(width, snap))

        plan = self._plan_block(snap)
        if plan:
            blocks.append(Text(""))
            blocks.extend(plan)

        blocks.append(Text(""))
        blocks.append(self._findings_line())
        blocks.append(self._budget_line())

        feed = self._feed_block(width, snap)
        if feed:
            # The activity feed is the most dispensable section: drop it
            # wholesale (or trailing lines) before letting the dashboard
            # outgrow the terminal and scroll itself offscreen.
            feed_allowance = max(0, min(len(feed), height - len(blocks) - 2))
            if feed_allowance:
                blocks.append(Text(""))
                blocks.append(Text("  ACTIVITY", style=f"bold {_GRAY}"))
                blocks.extend(feed[:feed_allowance])
        return blocks

    def _header_lines(self, width: int, targets: list[str]) -> list[Text]:
        lines: list[Text] = []
        head = Text("  ")
        head.append("STRIX", style=f"bold {_GREEN}")
        head.append("   ")
        head.append(spinner_frame(), style=f"bold {_GREEN}")
        head.append("  PENTEST IN PROGRESS", style=f"bold {_GREEN}")
        head.append(f"  ·  {_elapsed(self.state.started_monotonic)}", style=f"bold {_CYAN}")
        lines.append(head)

        info = Text("  ")
        info.append("run ", style=f"dim {_GRAY}")
        info.append(_clip(self.state.run_name, 32), style=f"bold {_CYAN}")
        info.append("   model ", style=f"dim {_GRAY}")
        info.append(_clip(self.state.model, 38), style="bold white")
        lines.append(info)

        target_line = Text("  ")
        target_line.append("targets ", style=f"dim {_GRAY}")
        if not targets:
            target_line.append("interactive (pending)", style=f"dim {_GRAY}")
        elif len(targets) == 1:
            target_line.append(_clip(targets[0], max(width - 18, 28)), style=f"bold {_BLUE}")
        else:
            joined = ", ".join(targets)
            target_line.append(f"{len(targets)} targets", style=f"bold {_BLUE}")
            target_line.append(f"   {joined}", style=f"dim {_GRAY}")
        lines.append(target_line)
        return lines

    @staticmethod
    def _divider(width: int) -> Text:
        return Text("  " + "─" * max(min(width - 4, 70), 12), style=f"dim {_GRAY}")
