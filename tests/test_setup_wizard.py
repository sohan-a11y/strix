"""Guided setup (`strix setup`) and the verified-connection preflight cache."""

from __future__ import annotations

import contextlib
import importlib
import json
import sys
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from rich.console import Console

from strix.config import loader
from strix.interface import environment, setup_wizard
from strix.interface.main import (
    _remember_verified_connection,
    _skip_preflight_when_still_verified,
)
from strix.interface.scan_setup import ModelConnectionError, llm_connection_fingerprint


if TYPE_CHECKING:
    from pathlib import Path
    from typing import IO

    from rich.text import Text


setup_wizard_module: Any = setup_wizard
model_config: Any = importlib.import_module("strix.config.models")

_MODEL = "openrouter/z-ai/glm-5.3"

_ENV_KEYS = [
    "STRIX_LLM",
    "LLM_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_KEY",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "STRIX_FALLBACK_LLMS",
]


@pytest.fixture(autouse=True)
def _isolated_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the config override at a per-test file and clear connection env."""
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    override = tmp_path / "cli-config.json"
    override.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(loader, "_override", override)
    monkeypatch.setattr(loader, "_cached", None)


class FakeConsole(Console):
    """Console double that renders output and replays canned answers into `input()` prompts."""

    def __init__(self, answers: list[str] | None = None) -> None:
        super().__init__(width=100, legacy_windows=False)
        self.answers = answers or []
        self.printed: list[str] = []

    def print(self, *args: Any, **kwargs: Any) -> None:
        # Render like a real console (Panels, Texts, markup) instead of
        # recording reprs, then split into lines for simple substring checks.
        with self.capture() as capture:
            super().print(*args, **kwargs)
        self.printed.extend(capture.get().splitlines())

    def input(
        self,
        prompt: str | Text = "",
        *,
        markup: bool = True,
        emoji: bool = True,
        password: bool = False,
        stream: IO[str] | None = None,
    ) -> str:
        return self.answers.pop(0) if self.answers else ""

    def status(self, *_args: Any, **_kwargs: Any) -> Any:
        return contextlib.nullcontext()


def _configure_connection(
    monkeypatch: pytest.MonkeyPatch,
    *,
    key: str = "sk-test",
    model: str = _MODEL,
    age: float = 0.0,
    api_base: str | None = None,
) -> None:
    """Set the connection env and store its (possibly aged) verified fingerprint."""
    monkeypatch.setenv("STRIX_LLM", model)
    monkeypatch.setenv("LLM_API_KEY", key)
    if api_base is None:
        monkeypatch.delenv("LLM_API_BASE", raising=False)
    else:
        monkeypatch.setenv("LLM_API_BASE", api_base)
    monkeypatch.setattr(loader, "_cached", None)
    payload = llm_connection_fingerprint(loader.load_settings())
    payload["verified_at"] = repr(time.time() - age)
    loader.store_verified_llm_connection(payload)
    monkeypatch.setattr(loader, "_cached", None)


# --------------------------------------------------------------------------- #
# wizard behavior
# --------------------------------------------------------------------------- #


def test_wizard_short_circuits_when_a_model_is_already_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", _MODEL)
    monkeypatch.setattr(loader, "_cached", None)

    def _no_prompts(*_args: Any) -> str:
        raise AssertionError("the wizard must not prompt")

    monkeypatch.setattr(setup_wizard, "_prompt_model", _no_prompts)

    assert setup_wizard.run_setup_wizard(FakeConsole()) is True


def test_wizard_collects_verifies_and_persists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted: list[str] = []
    stored: dict[str, Any] = {}
    preflights: list[str] = []

    monkeypatch.setattr(setup_wizard, "_prompt_model", lambda *_args: _MODEL)
    # Patch the singleton getpass module directly; `setup_wizard.getpass` is
    # the same module object, so the wizard observes the masked-key stub.
    monkeypatch.setattr("getpass.getpass", lambda *_args: "sk-wizard-secret")
    monkeypatch.setattr(setup_wizard, "persist_current", lambda: persisted.append("persist"))
    monkeypatch.setattr(setup_wizard, "store_verified_llm_connection", stored.update)
    monkeypatch.setattr(setup_wizard, "clear_verified_llm_connection", lambda: None)

    async def fake_preflight(model: str, settings: Any | None = None, **_kw: Any) -> None:
        assert settings is not None
        preflights.append(model)

    monkeypatch.setattr(setup_wizard, "preflight_model_connection", fake_preflight)
    monkeypatch.setattr(model_config, "configure_sdk_model_defaults", lambda _settings: None)

    console = FakeConsole()
    assert setup_wizard.run_setup_wizard(console) is True
    assert persisted == ["persist"]
    assert preflights == [_MODEL]
    assert stored["model"] == _MODEL
    assert stored["key_sha"] and "sk-wizard-secret" not in json.dumps(stored)
    assert any("Setup complete" in line for line in console.printed)


def test_three_failed_connections_raise_model_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted: list[str] = []

    monkeypatch.setattr(setup_wizard, "_prompt_model", lambda *_args: _MODEL)
    monkeypatch.setattr("getpass.getpass", lambda *_args: "sk-bad")
    monkeypatch.setattr(setup_wizard, "persist_current", lambda: persisted.append("persist"))

    async def failing_preflight(_model: str, _settings: Any | None = None, **_kw: Any) -> None:
        raise ConnectionError("connection refused")

    monkeypatch.setattr(setup_wizard, "preflight_model_connection", failing_preflight)

    console = FakeConsole(answers=[""])
    with pytest.raises(ModelConnectionError, match="connection refused"):
        setup_wizard.run_setup_wizard(console)
    assert persisted == []


def test_wizard_aborts_cleanly_when_the_model_prompt_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_wizard, "_prompt_model", lambda *_args: None)

    assert setup_wizard.run_setup_wizard(FakeConsole()) is False


def test_wizard_aborts_cleanly_when_the_key_prompt_is_interrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_wizard, "_prompt_model", lambda *_args: _MODEL)

    def interrupt(_prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("getpass.getpass", interrupt)

    assert setup_wizard.run_setup_wizard(FakeConsole()) is False


def test_wizard_points_at_auth_login_for_subscription_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_wizard, "_prompt_model", lambda *_args: "chatgpt/gpt-5.4")
    monkeypatch.setattr("strix.config.codex.is_authenticated", lambda: False)

    console = FakeConsole()
    assert setup_wizard.run_setup_wizard(console) is False
    assert any("strix auth login chatgpt" in line for line in console.printed)


def test_setup_command_exits_nonzero_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_wizard, "run_setup_wizard", lambda _console: False)

    assert setup_wizard.run_setup_command() == 1


def test_setup_command_succeeds_and_reports_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_wizard, "run_setup_wizard", lambda _console: True)
    monkeypatch.setenv("STRIX_LLM", _MODEL)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr("shutil.which", lambda _name: None)

    assert setup_wizard.run_setup_command() == 0


def test_environment_status_line_reports_setup_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", _MODEL)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr("shutil.which", lambda _name: None)

    line = setup_wizard.environment_status_line()

    assert "✗ Docker" in line.plain
    assert "✓ model" in line.plain
    assert _MODEL in line.plain


def test_can_prompt_requires_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(isatty=lambda: False))

    assert setup_wizard.can_prompt() is False


def test_sanitize_model_strips_quoting_and_whitespace() -> None:
    assert setup_wizard._sanitize_model(' "openrouter/z-ai/glm-5.3" ') == _MODEL
    assert setup_wizard._sanitize_model("chatgpt/gpt-5.4") == "chatgpt/gpt-5.4"
    assert setup_wizard._sanitize_model("   ") == ""


# --------------------------------------------------------------------------- #
# failover chain wizard
# --------------------------------------------------------------------------- #


_GEMINI_PRESET = "gemini/gemini-2.5-flash"


def _patch_chain_preflight(monkeypatch: pytest.MonkeyPatch, verified_models: list[str]) -> None:
    def fake_verify(entry: Any) -> None:
        verified_models.append(entry.model)

    monkeypatch.setattr(setup_wizard, "_verify_fallback", fake_verify)


def test_chain_wizard_saves_a_verified_preset(monkeypatch: pytest.MonkeyPatch) -> None:
    verified: list[str] = []
    _patch_chain_preflight(monkeypatch, verified)
    monkeypatch.setattr("getpass.getpass", lambda *_args: "cfg-gemini-key")

    console = FakeConsole(["y", "1", "", "D"])
    setup_wizard._configure_failover_chain(console)

    assert verified == [_GEMINI_PRESET]
    monkeypatch.setattr(loader, "_cached", None)
    entries = loader.load_settings().llm.fallbacks
    assert [spec.model for spec in entries] == [_GEMINI_PRESET]
    assert entries[0].api_key == "cfg-gemini-key"
    assert loader._override is not None
    saved = json.loads(loader._override.read_text(encoding="utf-8"))
    assert json.loads(saved["env"]["STRIX_FALLBACK_LLMS"]) == [
        spec.model_dump(mode="json") for spec in entries
    ]


def test_chain_wizard_skip_discards_unsaved_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified: list[str] = []
    _patch_chain_preflight(monkeypatch, verified)
    monkeypatch.setattr("getpass.getpass", lambda *_args: "cfg-gemini-key")

    console = FakeConsole(["y", "1", "", "S"])
    setup_wizard._configure_failover_chain(console)

    assert verified == [_GEMINI_PRESET]
    monkeypatch.setattr(loader, "_cached", None)
    assert loader.load_settings().llm.fallbacks == []
    assert loader._override is not None
    assert "STRIX_FALLBACK_LLMS" not in loader._override.read_text(encoding="utf-8")


def test_chain_wizard_default_answer_declines_the_offer() -> None:
    console = FakeConsole([])

    setup_wizard._configure_failover_chain(console)

    assert loader.load_settings().llm.fallbacks == []


class _EofConsole(FakeConsole):
    """Console double whose stdin is gone (EOF), like a closed pipe."""

    def input(
        self,
        prompt: str | Text = "",
        *,
        markup: bool = True,
        emoji: bool = True,
        password: bool = False,
        stream: IO[str] | None = None,
    ) -> str:
        raise EOFError


def test_chain_wizard_eof_aborts_the_offer() -> None:
    console = _EofConsole()

    with pytest.raises(setup_wizard_module._WizardAbortedError):
        setup_wizard._configure_failover_chain(console)


def test_setup_command_survives_eof_during_the_chain_offer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_wizard, "run_setup_wizard", lambda _console: True)
    monkeypatch.setenv("STRIX_LLM", _MODEL)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(setup_wizard, "Console", _EofConsole)

    assert setup_wizard.run_setup_command() == 0


# --------------------------------------------------------------------------- #
# validate_environment wires the wizard in
# --------------------------------------------------------------------------- #


def test_validate_environment_offers_the_wizard_to_terminal_users(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no model configured and a tty attached, the wizard runs once."""
    calls: list[str] = []
    monkeypatch.setattr(setup_wizard, "can_prompt", lambda: True)

    def running_wizard(_console: Console) -> bool:
        calls.append("wizard")
        return True

    monkeypatch.setattr(setup_wizard, "run_setup_wizard", running_wizard)

    environment.validate_environment()

    assert calls == ["wizard"]


def test_validate_environment_exits_when_the_wizard_fails_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported: list[str] = []
    panels: list[str] = []
    monkeypatch.setattr(setup_wizard, "can_prompt", lambda: True)

    def raising_wizard(_console: Console) -> bool:
        raise ModelConnectionError(_MODEL, RuntimeError("bad key"))

    cli_main: Any = importlib.import_module("strix.interface.main")

    monkeypatch.setattr(setup_wizard, "run_setup_wizard", raising_wizard)
    monkeypatch.setattr(
        environment, "report_error", lambda reason, _exc=None: reported.append(reason)
    )
    monkeypatch.setattr(
        cli_main,
        "_print_model_connection_error",
        lambda exc: panels.append(str(exc)),
    )

    with pytest.raises(SystemExit) as exit_info:
        environment.validate_environment()

    assert exit_info.value.code == 1
    assert reported == ["model_connection_failed"]
    assert panels


def test_validate_environment_keeps_the_headless_panel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported: list[str] = []
    monkeypatch.setattr(setup_wizard, "can_prompt", lambda: False)
    monkeypatch.setattr(
        environment, "report_error", lambda reason, _exc=None: reported.append(reason)
    )

    with pytest.raises(SystemExit) as exit_info:
        environment.validate_environment()

    assert exit_info.value.code == 1
    assert reported == ["missing_required_config"]


# --------------------------------------------------------------------------- #
# verified-connection cache
# --------------------------------------------------------------------------- #


def test_verified_connection_record_round_trip() -> None:
    payload = {"model": _MODEL, "key_sha": "abc123def4567890"}

    loader.store_verified_llm_connection(payload)

    assert loader.read_verified_llm_connection() == payload

    loader.clear_verified_llm_connection()

    assert loader.read_verified_llm_connection() is None


def test_preflight_skips_only_with_a_fresh_matching_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", _MODEL)
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setattr(loader, "_cached", None)

    # No record on file yet.
    assert _skip_preflight_when_still_verified(_MODEL) is False

    _configure_connection(monkeypatch)
    assert _skip_preflight_when_still_verified(_MODEL) is True


def test_a_changed_key_or_model_invalidates_the_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_connection(monkeypatch)

    monkeypatch.setenv("LLM_API_KEY", "sk-rotated")
    monkeypatch.setattr(loader, "_cached", None)
    assert _skip_preflight_when_still_verified(_MODEL) is False

    _configure_connection(monkeypatch)
    assert _skip_preflight_when_still_verified(_MODEL) is True

    monkeypatch.setenv("STRIX_LLM", "deepseek/deepseek-v4-pro")
    monkeypatch.setattr(loader, "_cached", None)
    assert _skip_preflight_when_still_verified("deepseek/deepseek-v4-pro") is False


def test_an_expired_record_re_preflights(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_connection(monkeypatch, age=8 * 24 * 3600.0)

    assert _skip_preflight_when_still_verified(_MODEL) is False


def test_a_future_dated_record_re_preflights(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_connection(monkeypatch, age=-3600.0)

    assert _skip_preflight_when_still_verified(_MODEL) is False


def test_subscription_models_always_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_connection(monkeypatch, model="chatgpt/gpt-5.4")

    assert _skip_preflight_when_still_verified("chatgpt/gpt-5.4") is False


def test_remember_stores_a_parsable_fingerprint_without_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", _MODEL)
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setattr(loader, "_cached", None)

    _remember_verified_connection()

    cached = loader.read_verified_llm_connection()
    assert cached is not None
    assert cached["model"] == _MODEL
    assert cached["key_sha"]
    assert float(str(cached["verified_at"])) > 0
    connection_fields = {key: value for key, value in cached.items() if key != "verified_at"}
    assert connection_fields == llm_connection_fingerprint(loader.load_settings())


def test_remember_ignores_subscription_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "chatgpt/gpt-5.4")
    monkeypatch.setattr(loader, "_cached", None)

    _remember_verified_connection()

    assert loader.read_verified_llm_connection() is None
