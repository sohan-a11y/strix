"""Single-step `--llm/--api-key/--api-base` flag wiring."""

from __future__ import annotations

import importlib
import os
import sys
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from argparse import Namespace


cli_args: Any = importlib.import_module("strix.interface.cli_args")
loader: Any = importlib.import_module("strix.config.loader")

_CONNECTION_KEYS = ("STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE")


@pytest.fixture(autouse=True)
def _clean_connection_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _CONNECTION_KEYS:
        monkeypatch.delenv(key, raising=False)


def _forget_connection_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dispose of env the parser sets directly (there was nothing before it)."""
    for key in _CONNECTION_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)


def _parse(monkeypatch: pytest.MonkeyPatch, *flags: str) -> tuple[Namespace, dict[str, str | None]]:
    """Parse one CLI invocation; return the args plus a post-parse env snapshot."""
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://example.com", *flags])
    monkeypatch.setattr(loader, "_cached", None)
    args = cli_args.parse_arguments()
    env_after = {key: os.environ.get(key) for key in _CONNECTION_KEYS}

    # The parser writes os.environ directly; nothing was there before, so the
    # values are ours to discard.
    for key in _CONNECTION_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    return args, env_after


def test_llm_flags_install_the_connection_and_reset_the_settings_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resets: list[int] = []
    monkeypatch.setattr(cli_args, "reset_settings_cache", lambda: resets.append(1))

    args, env_after = _parse(
        monkeypatch,
        "--llm",
        "openrouter/z-ai/glm-5.3",
        "--api-key",
        "sk-run",
        "--api-base",
        "https://api.local/v1",
    )

    assert args.llm == "openrouter/z-ai/glm-5.3"
    assert args.api_key == "sk-run"
    assert args.api_base == "https://api.local/v1"
    assert env_after.get("STRIX_LLM") == "openrouter/z-ai/glm-5.3"
    assert env_after.get("LLM_API_KEY") == "sk-run"
    assert env_after.get("LLM_API_BASE") == "https://api.local/v1"
    assert resets == [1]


def test_flags_without_values_do_not_touch_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resets: list[int] = []
    monkeypatch.setattr(cli_args, "reset_settings_cache", lambda: resets.append(1))

    args, env_after = _parse(monkeypatch)

    assert args.llm is None
    assert args.api_key is None
    assert args.api_base is None
    assert env_after["STRIX_LLM"] is None
    assert env_after["LLM_API_KEY"] is None
    assert env_after["LLM_API_BASE"] is None
    assert resets == []


def test_flag_values_beat_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "from-env")
    resets: list[int] = []
    monkeypatch.setattr(cli_args, "reset_settings_cache", lambda: resets.append(1))

    args, env_after = _parse(monkeypatch, "--llm", "from-flag")

    assert args.llm == "from-flag"
    assert env_after.get("STRIX_LLM") == "from-flag"
    assert resets == [1]
