"""First-run setup: one guided pass that collects and verifies an LLM connection.

``strix setup`` runs it explicitly; ``validate_environment`` runs it instead of
showing the missing-variable panel when a terminal is attached, so a fresh
machine converges in a single launch:

    strix -t https://app.com                      -> prompts once, saves, scans
    strix -t app.com --llm <model> --api-key <key> -> self-contained, no prompts

Everything the wizard learns is verified with one real model round-trip and
saved to ``~/.strix/cli-config.json`` (0600), so later runs are truly one step.
"""

from __future__ import annotations

import getpass
import logging
import os
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import codex, load_settings, persist_current
from strix.config.loader import (
    clear_verified_llm_connection,
    reset_settings_cache,
    save_llm_fallbacks,
    store_verified_llm_connection,
)
from strix.config.settings import LlmFallback
from strix.interface.scan_setup import (
    ModelConnectionError,
    llm_connection_fingerprint,
    preflight_model_connection,
)


logger = logging.getLogger(__name__)

_MODEL_PRESETS: tuple[tuple[str, str], ...] = (
    ("openrouter/z-ai/glm-5.3", "OpenRouter — free-tier friendly"),
    ("anthropic/claude-opus-4-7", "Anthropic"),
    ("openai/gpt-5.4", "OpenAI"),
    ("deepseek/deepseek-v4-pro", "DeepSeek"),
)

_WIZARD_MAX_ATTEMPTS = 3

# Free-quota providers offered as failover backups: (default model, hint).
_FAILOVER_PRESETS: tuple[tuple[str, str], ...] = (
    ("gemini/gemini-2.5-flash", "Google Gemini — AI Studio free tier"),
    ("groq/llama-3.3-70b-versatile", "Groq — free tier"),
)

_PROVIDER_KEY_HINTS: dict[str, str] = {
    "openrouter": "Create a key at https://openrouter.ai/keys",
    "anthropic": "https://console.anthropic.com/settings/keys",
    "openai": "https://platform.openai.com/api-keys",
    "deepseek": "https://platform.deepseek.com/api_keys",
    "gemini": "https://aistudio.google.com/apikey",
    "groq": "https://console.groq.com/keys",
}

_OK = "#22c55e"
_BAD = "red"


class _WizardAbortedError(Exception):
    """The user cancelled the wizard with Ctrl-C / EOF mid-prompt."""


def can_prompt() -> bool:
    """Whether an interactive user can answer questions in this session."""
    try:
        return bool(sys.stdin) and bool(sys.stdout) and sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError, OSError):  # pragma: no cover - closed streams
        return False


def is_model_configured() -> bool:
    """Whether the active configuration already names a model."""
    return bool((load_settings().llm.model or "").strip())


def run_setup_wizard(console: Console) -> bool:
    """Collect and verify an LLM connection interactively, then save it.

    Returns ``True`` when the configuration is ready (nothing was missing or
    the wizard finished); ``False`` when the user cancelled, in which case the
    caller should continue to its standard missing-configuration exit. Re-tries
    a failing connection a couple of times and finally raises
    :class:`ModelConnectionError`, so callers reuse their error rendering.
    """
    from strix.config.models import configure_sdk_model_defaults, is_known_openai_bare_model

    if is_model_configured():
        return True

    _print_intro(console)

    for attempt in range(1, _WIZARD_MAX_ATTEMPTS + 1):
        model = _prompt_model(console, is_known_openai_bare_model)
        if model is None:
            return False

        if codex.subscription_model(model) and not codex.is_authenticated():
            _print_subscription_hint(console, model)
            return False

        try:
            api_key, api_base = _prompt_credentials(console, model)
        except _WizardAbortedError:
            console.print()
            return False

        _install_choice(model, api_key, api_base, configure_sdk_model_defaults)

        console.print()
        with console.status("[bold cyan]Testing the model connection…[/]", spinner="dots"):
            try:
                _verify_connection()
            except Exception as exc:  # every failure is user-retryable
                if attempt >= _WIZARD_MAX_ATTEMPTS:
                    raise ModelConnectionError(model, exc) from exc
                logger.info("setup wizard: connection test failed (attempt %d)", attempt)
                _print_failure(console, str(exc))
            else:
                persist_current()
                store_verified_llm_connection(llm_connection_fingerprint(load_settings()))
                _print_success(console, model)
                try:
                    _configure_failover_chain(console)
                except _WizardAbortedError:
                    console.print()
                    console.print("[dim]Failover chain skipped.[/]")
                return True

    # Unreachable: every path inside the loop returns or raises.
    return False


def _print_intro(console: Console) -> None:
    intro = Text()
    intro.append("SETUP", style=f"bold {_OK}")
    intro.append("\n\n", style="white")
    intro.append(
        "Pick a model, paste its API key once, and Strix saves the connection "
        "so every future run is a single command:\n\n",
        style="white",
    )
    intro.append("    strix -t <target>\n", style=_OK)
    console.print("\n")
    console.print(
        Panel(
            intro,
            title="[bold white]STRIX",
            title_align="left",
            border_style=_OK,
            padding=(1, 2),
        )
    )


def _print_subscription_hint(console: Console, model: str) -> None:
    console.print()
    console.print(
        f"[yellow]{model}[/] uses the ChatGPT subscription. Sign in first, then re-run setup:"
    )
    console.print("  [cyan]strix auth login chatgpt[/]")


def _prompt_model(console: Console, is_known_openai_bare_model: Any) -> str | None:
    """Ask which model to use; ``None`` when the user aborts."""
    console.print("Model", style="dim")
    last = len(_MODEL_PRESETS)
    for index, (name, description) in enumerate(_MODEL_PRESETS, start=1):
        console.print(f"  [cyan]{index}[/]) {name}  [dim]{description}[/]")
    console.print(
        f"  [cyan]{last + 1}[/]) Other — enter a model id in the [cyan]provider/model[/] form"
    )

    while True:
        try:
            raw = console.input("Model choice [dim](1)[/]: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None
        if not raw or raw == "1":
            return _MODEL_PRESETS[0][0]
        if raw.isdigit():
            number = int(raw)
            if 1 <= number <= last:
                return _MODEL_PRESETS[number - 1][0]
            if number == last + 1:
                raw = ""
            else:
                console.print(f"[red]Enter a number between 1 and {last + 1}.[/]")
                continue
        if not raw:
            try:
                raw = console.input("Custom model id: ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                return None
        model = _sanitize_model(raw)
        if model and ("/" in model or is_known_openai_bare_model(model)):
            return model
        console.print(
            f"[yellow]'{model}' is not a recognizable model id.[/]  Use the "
            "[cyan]provider/model[/] form (e.g. [cyan]openrouter/z-ai/glm-5.3[/]) "
            "or an OpenAI name such as [cyan]gpt-5.4[/]."
        )


def _prompt_credentials(console: Console, model: str) -> tuple[str, str | None]:
    """Ask for the API key (masked) and an optional custom API base."""
    console.print()
    console.print(f"API key for [bold white]{model}[/]", style="dim")
    provider = model.split("/", 1)[0].lower()
    hint = _PROVIDER_KEY_HINTS.get(provider)
    if hint:
        console.print(f"  [dim]{hint}[/]")
    try:
        api_key = getpass.getpass("API key [Enter to skip]: ").strip()
    except (EOFError, KeyboardInterrupt) as exc:
        # getpass prints a newline on ^C while reading; treat both as an
        # abort of the whole wizard.
        raise _WizardAbortedError from exc

    console.print()
    try:
        raw_base = console.input(
            "Custom API base URL [dim](Enter for the provider default)[/]: "
        ).strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise _WizardAbortedError from exc
    api_base: str | None = _sanitize_model(raw_base) or None
    if api_base and not api_base.startswith(("http://", "https://")):
        console.print("[yellow]Base URLs should start with http:// or https://[/]")
    if api_base:
        api_base = api_base.rstrip("/")
    return api_key, api_base


def _print_failure(console: Console, error: str) -> None:
    text = Text()
    text.append("CONNECTION FAILED", style=f"bold {_BAD}")
    text.append("\n\n", style="white")
    text.append(error or "The model did not answer.", style="dim white")
    console.print("\n")
    console.print(text)


# ---- failover chain setup ---------------------------------------------------

_CHAIN_DONE = "done"
_CHAIN_SKIP = "skip"


def _ask(console: Console, prompt: str) -> str:
    """One line of console input; aborts the wizard on Ctrl-C / EOF / no tty."""
    try:
        return console.input(prompt).strip()
    except (EOFError, KeyboardInterrupt, OSError) as exc:
        raise _WizardAbortedError from exc


def _ask_model(console: Console, prompt: str, default: str | None = None) -> str:
    raw = _ask(console, prompt)
    if default and not raw:
        raw = default
    value = _sanitize_model(raw)
    if value and "/" not in value and not is_known_bare_name(value):
        console.print(
            f"[yellow]'{value}'[/] is not in the [cyan]provider/model[/] form — "
            "Strix will still try routing it."
        )
    return value


def is_known_bare_name(value: str) -> bool:
    """Whether ``value`` is a bare name LiteLLM/Strix can resolve on its own."""
    from strix.config.models import is_known_openai_bare_model

    return bool(is_known_openai_bare_model(value))


def _verify_fallback(entry: LlmFallback) -> None:
    """One tiny round-trip against a backup provider; raises on failure."""
    import asyncio

    from strix.config.models import StrixProvider
    from strix.interface.scan_setup import preflight_request

    model = StrixProvider(
        api_key=entry.api_key,
        base_url=entry.api_base,
        enable_failover=False,
    ).get_model(entry.model)
    try:
        asyncio.run(
            preflight_request(
                model,
                model_name=entry.model,
                extra_headers=None,
                extra_body=None,
                timeout=load_settings().llm.preflight_timeout,
                api_base_setting="LLM_API_BASE",
            )
        )
    except TimeoutError:
        raise TimeoutError(
            f"{entry.model} did not answer within "
            f"{load_settings().llm.preflight_timeout}s. Check the API key and "
            "endpoint, then try again (or answer S to skip it)."
        ) from None


def _prompt_entry_key(console: Console, model: str) -> LlmFallback:
    provider = model.split("/", 1)[0].lower()
    hint = _PROVIDER_KEY_HINTS.get(provider)
    if hint:
        console.print(f"  [dim]{hint}[/]")
    try:
        api_key = getpass.getpass("API key: ").strip()
    except (EOFError, KeyboardInterrupt, OSError) as exc:
        raise _WizardAbortedError from exc
    return LlmFallback(model=model, api_key=api_key or None)


def _prompt_custom_endpoint(console: Console) -> LlmFallback | None:
    console.print()
    console.print("OpenAI-compatible backup endpoint", style="dim")
    raw_base = _sanitize_model(_ask(console, "API base URL: ").rstrip("/"))
    if not raw_base.startswith(("http://", "https://")):
        console.print("[red]Base URLs must start with http:// or https://[/]")
        return None
    model = _ask_model(console, "Model id [dim](provider/model)[/]: ")
    if not model:
        console.print("[red]A model id is required.[/]")
        return None
    return _prompt_entry_key(console, model)


def _prompt_failover_entry(console: Console) -> LlmFallback | str:
    """Ask for one backup provider; ``_CHAIN_DONE``/``_CHAIN_SKIP`` to stop.

    ``_CHAIN_DONE`` keeps the entries collected so far and saves them;
    ``_CHAIN_SKIP`` discards what was added in this session.
    """
    console.print()
    console.print("Backup provider", style="dim")
    total = len(_FAILOVER_PRESETS)
    for index, (model, description) in enumerate(_FAILOVER_PRESETS, start=1):
        console.print(f"  [cyan]{index}[/]) {model}  [dim]{description}[/]")
    console.print(f"  [cyan]{total + 1}[/]) Other — OpenAI-compatible endpoint (custom base URL)")
    console.print("  [cyan]D[/]) Done — save the chain")
    console.print("  [cyan]S[/]) Skip — discard the backups added just now")
    while True:
        raw = _ask(console, "Backup provider choice [dim](D)[/]: ").lower()
        if raw in {"", "d"}:
            return _CHAIN_DONE
        if raw == "s":
            return _CHAIN_SKIP
        if raw.isdigit():
            choice = int(raw)
            if 1 <= choice <= total:
                default_model, _ = _FAILOVER_PRESETS[choice - 1]
                entry_model = _ask_model(
                    console,
                    f"Model [dim](Enter = {default_model})[/]: ",
                    default=default_model,
                )
                if not entry_model:
                    console.print("[red]A model id is required.[/]")
                    continue
                return _prompt_entry_key(console, entry_model)
            if choice == total + 1:
                return _prompt_custom_endpoint(console) or _CHAIN_DONE
            console.print(f"[red]Enter 1-{total + 1}, D or S.[/]")
            continue
        console.print("[red]Enter a number, D or S.[/]")


def _configure_failover_chain(
    console: Console,
    *,
    heading: str = "Free-quota failover (optional)",
) -> None:
    """Offer sticky failover backups; persist confirmed entries in one write."""
    entries: list[LlmFallback] = list(load_settings().llm.fallbacks)
    if entries:
        console.print()
        console.print("Current failover chain", style="dim")
        for spec in entries:
            console.print(f"  · {spec.display_name()}")
    console.print()
    console.print(heading, style="bold white")
    console.print(
        "If the main provider runs out of free quota mid-scan, Strix switches to "
        "the next provider automatically and keeps scanning.\n"
        "Accept [cyan]y[/] to add backups (e.g. TokenRouter → Gemini → Groq); "
        "[dim]Enter = no[/]."
    )
    answer = _ask(console, "Set up a failover chain? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        return
    added_any = False
    while True:
        outcome = _prompt_failover_entry(console)
        if isinstance(outcome, LlmFallback):
            console.print()
            verified = False
            with console.status("[bold cyan]Testing the backup connection…[/]", spinner="dots"):
                try:
                    _verify_fallback(outcome)
                except Exception as exc:  # every failure is user-retryable
                    logger.info("failover entry %s failed preflight", outcome.model)
                    _print_failure(console, str(exc))
                else:
                    verified = True
            # Unverified entries are dropped so the chain never contains a dead key.
            if verified:
                entries.append(outcome)
                added_any = True
                console.print(f"[green]✓[/] added [white]{outcome.display_name()}[/] to the chain")
            continue
        if outcome == _CHAIN_SKIP:
            return
        break  # _CHAIN_DONE: keep the entries collected so far
    if not entries:
        return
    save_llm_fallbacks([entry.model_dump(mode="json") for entry in entries])
    # The same process can go straight into a scan (validate_environment run
    # path), so the freshly saved chain must be visible to settings readers.
    reset_settings_cache()
    console.print()
    console.print("Failover chain", style="dim")
    for order, spec in enumerate(entries, start=1):
        console.print(f"  {order}. {spec.display_name()}")
    console.print()
    summary = Text()
    summary.append("✓ Saved", style=f"bold {_OK}")
    summary.append(f"  backups {len(entries)} — added {added_any}", style="dim white")
    summary.append("  (~/.strix/cli-config.json)", style="dim white")
    console.print(summary)


def _print_success(console: Console, model: str) -> None:
    saved = Text()
    saved.append("Setup complete", style=f"bold {_OK}")
    saved.append("\n\n", style="white")

    saved_model = Text()
    saved_model.append("Model   ", style="dim")
    saved_model.append(model, style="bold white")
    saved_model.append("\n")
    saved_model.append("Saved   ", style="dim")
    saved_model.append("~/.strix/cli-config.json", style="white")

    console.print()
    console.print(
        Panel(
            Text.assemble(saved, saved_model),
            title="[bold white]STRIX",
            title_align="left",
            border_style=_OK,
            padding=(1, 2),
        )
    )


def _install_choice(
    model: str, api_key: str, api_base: str | None, configure_defaults: Any
) -> None:
    """Install the answers into the process environment and refresh settings."""
    os.environ["STRIX_LLM"] = model
    if api_key:
        os.environ["LLM_API_KEY"] = api_key
    if api_base:
        os.environ["LLM_API_BASE"] = api_base
    reset_settings_cache()
    clear_verified_llm_connection()  # the previous connection note no longer applies
    configure_defaults(load_settings())


def _verify_connection() -> None:
    """One tiny model round-trip; raises on failure so callers can retry/abort."""
    import asyncio

    settings = load_settings()
    model = (settings.llm.model or "").strip()
    asyncio.run(preflight_model_connection(model, settings=settings))


def _sanitize_model(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1].strip()
    return "".join(value.split())


# ---- standalone ``strix setup`` entry point ------------------------------


def run_setup_command() -> int:
    """Implement ``strix setup``: configure, verify, and report setup health."""
    console = Console()

    console.print()
    if not run_setup_wizard(console):
        return 1

    if is_model_configured():
        # The wizard short-circuits when a model is already saved; this is the
        # only interactive chance to add or extend the failover chain.
        console.print()
        try:
            _configure_failover_chain(console, heading="Failover chain")
        except _WizardAbortedError:
            console.print()
            console.print("[dim]Failover chain skipped.[/]")

    console.print()
    console.print("Environment", style="dim")
    console.print(f"  {environment_status_line()}")

    if not (load_settings().llm.api_key or os.environ.get("OPENAI_API_KEY")):
        console.print(
            "[dim]No API key saved. Keys already present as OPENAI_API_KEY are used "
            "automatically; local endpoints set their base URL with "
            "[cyan]--api-base[/].[/]"
        )
    console.print()
    console.print("Next: ", style="dim", end="")
    console.print("[cyan]strix -t <target>[/]")
    return 0


def environment_status_line() -> Text:
    """One colored status row of the critical local prerequisites."""
    import shutil

    text = Text()
    docker_installed = shutil.which("docker") is not None
    text.append("✓" if docker_installed else "✗", style=_OK if docker_installed else _BAD)
    text.append(" Docker", style="white")
    if docker_installed:
        daemon_up, image_ready = _docker_state()
        if daemon_up:
            text.append("  ✓ daemon", style=_OK)
            image_style = _OK if image_ready else "dim"
            text.append(f"  {'✓' if image_ready else '○'} sandbox image", style=image_style)
        else:
            text.append("  ✗ daemon not reachable", style=_BAD)
    model = (load_settings().llm.model or "").strip()
    text.append("  ·  ", style="dim")
    text.append("✓" if model else "✗", style=_OK if model else _BAD)
    text.append(" model", style="white")
    if model:
        text.append(f" ({model})", style="dim")
    return text


def _docker_state() -> tuple[bool, bool]:
    try:
        from strix.interface.utils import image_exists
        from strix.runtime.docker_connection import connect_docker

        client = connect_docker()
        return True, image_exists(client, load_settings().runtime.image)
    except Exception:
        logger.debug("docker state probe failed", exc_info=True)
        return False, False
