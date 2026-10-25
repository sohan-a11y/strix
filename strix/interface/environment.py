"""Startup environment validation, guided setup, and Docker image management."""

from __future__ import annotations

import logging
import shutil
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import IntegrationSettings, codex, load_settings
from strix.interface import setup_wizard
from strix.interface.scan_setup import ModelConnectionError
from strix.interface.utils import (
    check_docker_connection,
    image_exists,
    process_pull_line,
)
from strix.telemetry import report_error


logger = logging.getLogger(__name__)


def _missing_web_search_vars(integrations: IntegrationSettings) -> list[str]:
    """Mirror the web_search provider rules: which key(s) the selected provider needs."""
    if integrations.web_search_provider == "exa":
        return [] if integrations.exa_api_key else ["EXA_API_KEY"]
    if integrations.web_search_provider == "perplexity":
        return [] if integrations.perplexity_api_key else ["PERPLEXITY_API_KEY"]
    if integrations.exa_api_key or integrations.perplexity_api_key:
        return []
    return ["EXA_API_KEY", "PERPLEXITY_API_KEY"]


class EnvironmentIssues:
    """Aggregated startup problems so a broken setup is explained in one screen."""

    def __init__(self) -> None:
        model = _active_model()
        self.subscription_not_signed_in = False
        if model and codex.subscription_model(model) and not codex.is_authenticated():
            self.subscription_not_signed_in = True
        self.missing_required: list[str] = (
            [] if model or self.subscription_not_signed_in else ["STRIX_LLM"]
        )
        self.missing_optional: list[str] = self._collect_optional()

    @property
    def has_blockers(self) -> bool:
        return bool(self.missing_required) or self.subscription_not_signed_in

    def _collect_optional(self) -> list[str]:
        settings = load_settings()
        missing: list[str] = []
        if not settings.llm.api_key:
            missing.append("LLM_API_KEY")
        if not settings.llm.api_base:
            missing.append("LLM_API_BASE")
        missing.extend(_missing_web_search_vars(settings.integrations))
        return missing


def _active_model() -> str:
    try:
        return (load_settings().llm.model or "").strip()
    except Exception:  # validation must never crash the CLI
        logger.exception("reading the configured model failed")
        return ""


def validate_environment() -> None:
    """Fail only on problems that make a run impossible; offer the setup wizard.

    The wizard runs whenever a terminal user can answer it, turning the old
    error-and-exit ladder into a single guided pass that persists the missing
    values. Headless (no tty) sessions keep the informative panel directly.
    """
    logger.info("Validating environment")
    issues = EnvironmentIssues()
    if not issues.has_blockers:
        return

    if setup_wizard.can_prompt():
        try:
            if setup_wizard.run_setup_wizard(Console()):
                return
        except ModelConnectionError as exc:
            report_error("model_connection_failed", exc)
            from strix.interface.main import _print_model_connection_error

            _print_model_connection_error(exc)
            sys.exit(1)

    report_error("missing_required_config")
    _print_missing_configuration_panel(issues)
    sys.exit(1)


def _print_missing_configuration_panel(issues: EnvironmentIssues) -> None:
    console = Console()
    error_text = Text()
    error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
    error_text.append("\n\n", style="white")

    if issues.subscription_not_signed_in:
        error_text.append(
            f"• STRIX_LLM={load_settings().llm.model} uses your ChatGPT subscription, "
            "but you are not signed in\n",
            style="bold yellow",
        )
    for var in issues.missing_required:
        error_text.append(f"• {var}", style="bold yellow")
        error_text.append(" is not set\n", style="white")

    if issues.missing_optional:
        error_text.append("\nOptional environment variables:\n", style="dim white")
        for var in issues.missing_optional:
            error_text.append(f"• {var}", style="dim yellow")
            error_text.append(" is not set\n", style="dim white")

    error_text.append("\nRequired variable:\n", style="white")
    error_text.append("• ", style="white")
    error_text.append("STRIX_LLM", style="bold cyan")
    error_text.append(
        " - Model name to use (e.g., 'openrouter/z-ai/glm-5.3' or 'anthropic/claude-opus-4-7')\n",
        style="white",
    )

    if issues.missing_optional:
        error_text.append("\nOptional environment variables:\n", style="white")
        _optional_descriptions(issues.missing_optional, error_text)

    error_text.append("\nFix it with one command:\n", style="white")
    error_text.append("strix setup\n", style="dim white")
    error_text.append("\nOr inline for a single run:\n", style="white")
    error_text.append(
        "strix -t <target> --llm 'openrouter/z-ai/glm-5.3' --api-key 'your-key'\n",
        style="dim white",
    )

    panel = Panel(
        error_text,
        title="[bold white]STRIX",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )

    logger.debug("Missing required env vars: %s", issues.missing_required)
    console.print("\n")
    console.print(panel)
    console.print()


def _optional_descriptions(missing_optional: list[str], error_text: Text) -> None:
    const_descriptors: dict[str, str] = {
        "LLM_API_BASE": (" - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n"),
        "LLM_API_KEY": " - API key for the selected model provider\n",
        "PERPLEXITY_API_KEY": (" - API key for Perplexity AI web search (alternative to Exa)\n"),
        "EXA_API_KEY": " - API key for Exa web search (enables real-time research)\n",
        "STRIX_REASONING_EFFORT": (
            " - Reasoning effort level: none, minimal, low, medium, high, xhigh, "
            "max (default: high)\n"
        ),
    }
    for var in missing_optional:
        error_text.append("• ", style="white")
        error_text.append(var, style="bold cyan")
        if descriptor := const_descriptors.get(var):
            error_text.append(descriptor, style="white")
        else:
            error_text.append(" is not set\n", style="white")


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.debug("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n",
            style="white",
        )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        report_error("docker_not_installed")
        sys.exit(1)
    logger.debug("Docker CLI present")


# ---- Docker image pull: background start + join, so setup runs alongside ---


class _NullStatus:
    """Absorb ``process_pull_line`` render calls in the background thread."""

    def update(self, *_args: Any) -> None:
        return


class _ImagePull(threading.Thread):
    """Stream the sandbox image pull in the background, reporting layer progress."""

    def __init__(self, image: str, client: Any) -> None:
        super().__init__(name="strix-image-pull", daemon=True)
        self.image = image
        self.client = client
        self.progress: dict[str, str] = {}
        self._status_view = _NullStatus()
        self.last_update = ""
        self.error: BaseException | None = None
        self.done = threading.Event()

    def run(self) -> None:
        try:
            for line in self.client.api.pull(self.image, stream=True, decode=True):
                self.last_update = process_pull_line(
                    line, self.progress, self._status_view, self.last_update
                )
        except Exception as exc:  # surfaced by the joining thread
            self.error = exc
        finally:
            self.done.set()

    def summary(self) -> str:
        completed = sum(1 for value in self.progress.values() if value == "✓")
        total = len(self.progress)
        if not total:
            return "Fetching image manifest…"
        return f"Downloading layers  {completed}/{total} complete"


def start_image_pull_background() -> _ImagePull | None:
    """Start pulling the sandbox image now if it is absent; ``None`` if not needed.

    The daemon probe runs here (main thread) so an unreachable Docker still
    produces its existing explanatory panel before anything else happens.
    """
    client = check_docker_connection()
    image = load_settings().runtime.image
    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return None
    logger.info("Starting background docker image pull: %s", image)
    pull = _ImagePull(image, client)
    pull.start()
    return pull


def finish_image_pull_background(pull: _ImagePull | None) -> None:
    """Render pull progress until the daemon finishes importing the layers."""
    if pull is None:
        return
    console = Console()
    console.print()
    console.print(f"[dim]Pulling image[/] {pull.image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        last_text = "[bold cyan]Downloading image layers..."
        while not pull.done.is_set():
            progress = pull.summary()
            if progress != last_text:
                last_text = progress
                status.update(f"[bold cyan]{progress}")
            time.sleep(0.5)

        if pull.error is not None:
            _print_pull_failure(console, pull.error)
            report_error("image_pull_failed", pull.error)
            sys.exit(1)

    logger.info("Docker image %s ready", pull.image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def _print_pull_failure(console: Console, error: BaseException) -> None:
    logger.debug("Failed to pull docker image", exc_info=True)
    error_text = Text()
    error_text.append("FAILED TO PULL IMAGE", style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(f"Could not download: {load_settings().runtime.image}\n", style="white")
    error_text.append(str(error), style="dim red")

    panel = Panel(
        error_text,
        title="[bold white]STRIX",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print(panel, "\n")


def pull_docker_image() -> None:
    """Synchronous convenience wrapper: start, join, and verify in one call."""
    finish_image_pull_background(start_image_pull_background())
