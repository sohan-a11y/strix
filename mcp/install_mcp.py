"""Register the Strix MCP server in this project's OpenCode config.

Idempotent: creates or updates opencode.json at the repo root, preserving
any existing top-level configuration keys.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SERVER_NAME = "strix"


def _venv_python() -> Path:
    for candidate in (_VENV / "Scripts" / "python.exe", _VENV / "bin" / "python"):
        if candidate.exists():
            return candidate.resolve()
    sys.exit("[!] .venv not found - run setup.ps1 (or create .venv) first")


_VENV = ROOT / ".venv"
_CONFIG = ROOT / "opencode.json"


def main() -> None:
    venv_python = _venv_python()
    server_py = ROOT / "mcp" / "server.py"

    existing: dict = {}
    if _CONFIG.exists():
        try:
            existing = json.loads(_CONFIG.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            sys.exit(
                "[!] opencode.json exists but is not plain JSON (JSONC comments "
                "are not merged here). Move MCP config elsewhere or edit by hand."
            )

    servers: dict = existing.setdefault("mcp", {}).setdefault("servers", {})
    servers[SERVER_NAME] = {
        "type": "local",
        "command": [str(venv_python), str(server_py)],
        "cwd": str(ROOT),
        "codemode": False,
        "timeout": {"startup": 120_000},
    }
    existing.setdefault("$schema", "https://opencode.ai/config.json")

    _CONFIG.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Registered MCP server '{SERVER_NAME}' in {_CONFIG}")


if __name__ == "__main__":
    main()
