"""Register the Strix MCP server in coding agent configs (Google Antigravity & OpenCode).

Idempotent: creates or updates opencode.json and .agents/mcp_config.json,
preserving any existing configuration keys or servers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "strix"
_VENV = ROOT / ".venv"


def _venv_python() -> Path:
    for candidate in (_VENV / "Scripts" / "python.exe", _VENV / "bin" / "python"):
        if candidate.exists():
            return candidate.resolve()
    sys.exit("[!] .venv not found - run setup.ps1 (or create .venv) first")


def install_opencode(venv_python: Path, server_py: Path) -> None:
    config_path = ROOT / "opencode.json"
    existing: dict = {}
    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            print(
                f"[!] {config_path} exists but is not plain JSON. Skipping OpenCode registration."
            )
            return

    mcp_block: dict = existing.setdefault("mcp", {})
    if not isinstance(mcp_block, dict):
        mcp_block = {}
        existing["mcp"] = mcp_block
    servers: dict = mcp_block.setdefault("servers", {})
    if not isinstance(servers, dict):
        servers = {}
        mcp_block["servers"] = servers
    # OpenCode's deprecated shape (mcp.<name> directly) rejects `codemode` and
    # an object `timeout`, so an old entry there is dead weight: drop ours.
    mcp_block.pop(SERVER_NAME, None)
    servers[SERVER_NAME] = {
        "type": "local",
        "command": [str(venv_python), str(server_py)],
        "cwd": str(ROOT),
        "codemode": False,
        "timeout": {"startup": 120_000},
    }
    existing.setdefault("$schema", "https://opencode.ai/config.json")

    config_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Registered MCP server '{SERVER_NAME}' in OpenCode config: {config_path}")


def install_antigravity(venv_python: Path, server_py: Path, global_config: bool = False) -> None:
    target_configs: list[Path] = [ROOT / ".agents" / "mcp_config.json"]

    if global_config:
        global_path = Path.home() / ".gemini" / "config" / "mcp_config.json"
        target_configs.append(global_path)

    for config_path in target_configs:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        existing: dict = {}
        if config_path.exists():
            try:
                existing = json.loads(config_path.read_text(encoding="utf-8"))
                if not isinstance(existing, dict):
                    existing = {}
            except json.JSONDecodeError:
                print(f"[!] {config_path} exists but is not valid JSON. Skipping {config_path}.")
                continue

        servers: dict = existing.setdefault("mcpServers", {})
        servers[SERVER_NAME] = {
            "command": str(venv_python),
            "args": [str(server_py)],
            "cwd": str(ROOT),
            "env": {"PYTHONUTF8": "1"},
        }

        config_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        print(f"[+] Registered MCP server '{SERVER_NAME}' in Antigravity config: {config_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Register the Strix MCP server in OpenCode and/or Google Antigravity configs."
    )
    parser.add_argument(
        "--target",
        choices=["all", "antigravity", "opencode"],
        default="all",
        help="Which agent platform config to update (default: all)",
    )
    parser.add_argument(
        "--global",
        dest="global_config",
        action="store_true",
        help="Also register in global Antigravity config (~/.gemini/config/mcp_config.json)",
    )

    args = parser.parse_args()
    venv_python = _venv_python()
    server_py = ROOT / "mcp" / "server.py"

    if args.target in ("all", "opencode"):
        install_opencode(venv_python, server_py)

    if args.target in ("all", "antigravity"):
        install_antigravity(venv_python, server_py, global_config=args.global_config)


if __name__ == "__main__":
    main()
