"""Smoke test: spawns mcp/server.py over stdio and exercises the tools.

Run with the repo venv: .venv/Scripts/python.exe mcp/smoke_test.py
Safe to re-run; requires Docker up and the sandbox image pulled for the
exec test (health + tools list run anywhere).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


def _venv_python() -> str:
    for candidate in (
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ):
        if candidate.exists():
            return str(candidate)
    sys.exit("[!] run inside the repo (needs .venv)")


async def main() -> int:
    params = StdioServerParameters(
        command=_venv_python(),
        args=[str(ROOT / "mcp" / "server.py")],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("tools:", json.dumps(names, indent=2))
            assert "sandbox_health" in names, "missing sandbox_health"

            health = await session.call_tool("sandbox_health", {})
            print("health:", health.content[0].text)

            exec_res = await session.call_tool(
                "sandbox_exec",
                {"command": "echo smoke-ok && nmap --version | head -n 2"},
            )
            print("exec:", exec_res.content[0].text)
            return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
