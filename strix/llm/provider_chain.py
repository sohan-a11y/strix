"""Sticky multi-provider failover for the active LLM chain.

A scan can outlive one provider's free quota. ``FailoverModel`` fronts the
configured chain — main connection first, then the ``STRIX_FALLBACK_LLMS``
backups (e.g. TokenRouter → Gemini free tier → Groq free tier) — and hands the
turn to the first provider that still answers. The agent runner re-invokes a
model per retry attempt (``agents.run_internal.model_retry``), so each
attempted call runs the cascade again and an exhausted primary is skipped.

Switch policy (sticky, per process):
- A provider that keeps failing rate-limit checks is declared exhausted after
  ``FAIL_STREAK_THRESHOLD`` consecutive failures inside a five-minute window
  (transient blips recover and are never declared dead).
- A dead key (auth error) or a billing/permission refusal exhausts a provider
  immediately.
- Once exhausted, an entry stays out of rotation until the process ends; the
  next ``strix --resume`` starts fresh at the primary.

Every exhaustion fires the registered listeners so the headless dashboard can
render the switch in its status line, and the default listener logs the switch.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agents.models.interface import Model
from openai import (
    APIStatusError,
    AuthenticationError,
    PermissionDeniedError,
    RateLimitError,
)

from strix.config.settings import LlmFallback


if TYPE_CHECKING:
    from agents.agent_output import AgentOutputSchemaBase
    from agents.handoffs import Handoff
    from agents.items import ModelResponse, TResponseInputItem, TResponseStreamEvent
    from agents.model_settings import ModelSettings
    from agents.models.interface import ModelTracing
    from agents.retry import ModelRetryAdvice, ModelRetryAdviceRequest
    from agents.tool import Tool
    from openai.types.responses.response_prompt_param import ResponsePromptParam

    from strix.config.settings import LlmSettings


logger = logging.getLogger(__name__)

FAIL_STREAK_THRESHOLD = 3
FAIL_STREAK_WINDOW_SECONDS = 300.0

_AUDIT_KEY_LENGTH = 16


def _provider_key(spec: LlmFallback) -> str:
    """Stable identity for a provider spec (the API key itself is never stored raw)."""
    key_material = hashlib.sha256((spec.api_key or "").encode("utf-8", "replace")).digest()
    digest = hashlib.blake2s(digest_size=_AUDIT_KEY_LENGTH)
    digest.update(spec.model.encode("utf-8", "replace"))
    digest.update(b"|")
    digest.update(key_material)
    digest.update(b"|")
    digest.update((spec.api_base or "").encode("utf-8", "replace"))
    return digest.hexdigest()


# ---- provider health state (module-level, process lifetime) ----------------


@dataclass
class _Streak:
    timestamps: list[float] = field(default_factory=list)


_STREAKS: dict[str, _Streak] = {}
_EXHAUSTED: dict[str, str] = {}
_STATE_LOCK = threading.RLock()


def _default_listener(from_label: str, to_label: str, reason: str) -> None:
    logger.warning(
        "LLM provider switched: %s is exhausted (%s); continuing with %s",
        from_label,
        reason,
        to_label,
    )


SwitchListener = Callable[[str, str, str], None]
_LISTENERS: list[SwitchListener] = [_default_listener]


def add_provider_switch_listener(listener: SwitchListener) -> Callable[[], None]:
    """Add ``listener(from_label, to_label, reason)``; return an unsubscribe."""
    _LISTENERS.append(listener)
    return lambda: _LISTENERS.remove(listener)


def _notify_switch(from_label: str, to_label: str, reason: str) -> None:
    for listener in tuple(_LISTENERS):
        try:
            listener(from_label, to_label, reason)
        except Exception:  # noqa: BLE001 - listeners must never break a scan
            logger.warning("provider switch listener failed", exc_info=True)


def _decay(streak: _Streak, now: float) -> list[float]:
    return [stamp for stamp in streak.timestamps if now - stamp <= FAIL_STREAK_WINDOW_SECONDS]


def _mark_exhausted(key: str, reason: str) -> None:
    _EXHAUSTED[key] = reason
    _STREAKS.pop(key, None)


def _record_rate_limit_failure(key: str) -> bool:
    """Count one more rate-limit failure; ``True`` once the provider tips over."""
    now = time.monotonic()
    with _STATE_LOCK:
        if key in _EXHAUSTED:
            return False
        streak = _STREAKS.setdefault(key, _Streak())
        streak.timestamps = _decay(streak, now)
        streak.timestamps.append(now)
        if len(streak.timestamps) < FAIL_STREAK_THRESHOLD:
            return False
        _mark_exhausted(key, "rate limit")
        return True


def _record_immediate_failure(key: str, reason: str) -> bool:
    with _STATE_LOCK:
        if key in _EXHAUSTED:
            return False
        _mark_exhausted(key, reason)
        return True


def _record_success(key: str) -> None:
    with _STATE_LOCK:
        _STREAKS.pop(key, None)


def _is_exhausted(key: str) -> str | None:
    with _STATE_LOCK:
        return _EXHAUSTED.get(key)


def reset_failover_state() -> None:
    """Forget every exhaustion mark; used at scan start."""
    with _STATE_LOCK:
        _STREAKS.clear()
        _EXHAUSTED.clear()


# ---- error classification ---------------------------------------------------


def _classify_error(exc: BaseException) -> str | None:
    """Map a provider exception to a chain action, or ``None`` to pass through.

    Rate limits accumulate toward the streak threshold; dead keys and
    billing/permission walls remove a provider on first sight.
    """
    if isinstance(exc, RateLimitError):
        return "rate_limit_streak"
    if isinstance(exc, AuthenticationError):
        return "authentication"
    if isinstance(exc, APIStatusError) and exc.status_code == 402:
        return "billing"
    if isinstance(exc, PermissionDeniedError):
        return "permission"
    return None


def _record_failure_with_reason(key: str, exc: BaseException) -> str | None:
    kind = _classify_error(exc)
    if kind == "rate_limit_streak":
        return "rate limit wall" if _record_rate_limit_failure(key) else None
    reasons = {
        "authentication": "authentication failure",
        "billing": "billing/quota limit",
        "permission": "permission denied",
    }
    reason = reasons.get(kind or "")
    return reason if reason and _record_immediate_failure(key, reason) else None


# ---- model -------------------------------------------------------------------


@dataclass
class _Entry:
    key: str
    label: str
    spec: LlmFallback | None
    model: Model | None
    builder: Callable[[LlmFallback], Model] | None = None


class FailoverModel(Model):
    """Front the provider chain: primary first, backups only when the primary fails.

    Lazy backup construction keeps a wrapped model cheap; the builder is a seam
    that tests replace with stubs.
    """

    def __init__(
        self,
        primary: Model,
        *,
        primary_label: str,
        primary_key: str,
        fallbacks: Sequence[LlmFallback],
        delegate_builder: Callable[[LlmFallback], Model],
    ) -> None:
        self._entries: list[_Entry] = [
            _Entry(key=primary_key, label=primary_label, spec=None, model=primary)
        ]
        for spec in fallbacks:
            self._entries.append(
                _Entry(
                    key=_provider_key(spec),
                    label=spec.display_name(),
                    spec=spec,
                    model=None,
                    builder=delegate_builder,
                )
            )

    def _candidate_indexes(self) -> Iterator[int]:
        for index, entry in enumerate(self._entries):
            if _is_exhausted(entry.key) is None:
                yield index

    def _next_candidate_label(self, after: int) -> str:
        for index in self._candidate_indexes():
            if index > after:
                return self._entries[index].label
        return "(no fallback left)"

    def _ensure(self, index: int) -> Model:
        entry = self._entries[index]
        if entry.model is not None:
            return entry.model
        if entry.spec is None or entry.builder is None:
            raise RuntimeError(f"provider entry {index!r} has no model and no builder")
        entry.model = entry.builder(entry.spec)
        return entry.model

    # ---- failure bookkeeping

    def _note_failure(self, index: int, exc: BaseException) -> None:
        reason = _record_failure_with_reason(self._entries[index].key, exc)
        if reason is None:
            logger.debug("provider %s was rate-limited: %s", self._entries[index].label, exc)
            return
        logger.warning(
            "provider %s is out for the rest of this scan: %s",
            self._entries[index].label,
            reason,
        )
        _notify_switch(
            self._entries[index].label,
            self._next_candidate_label(index),
            reason,
        )

    def _note_success(self, index: int) -> None:
        _record_success(self._entries[index].key)

    # ---- Model interface

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        last_error: Exception | None = None
        for index in self._candidate_indexes():
            try:
                delegate = self._ensure(index)
            except Exception as build_error:  # noqa: BLE001 - try the next provider
                last_error = build_error
                continue
            try:
                response = await delegate.get_response(
                    system_instructions,
                    input,
                    model_settings,
                    tools,
                    output_schema,
                    handoffs,
                    tracing,
                    previous_response_id=previous_response_id,
                    conversation_id=conversation_id,
                    prompt=prompt,
                )
            except Exception as exc:
                if _classify_error(exc) is None:
                    raise
                last_error = exc
                self._note_failure(index, exc)
                continue
            self._note_success(index)
            return response
        if last_error is not None:
            raise last_error
        raise RuntimeError(
            "every LLM provider in the configured chain is exhausted "
            "(rate limit / quota); resume with 'strix --resume <run-name>' "
            "once a limit clears"
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        last_error: Exception | None = None
        for index in self._candidate_indexes():
            started = False
            try:
                delegate = self._ensure(index)
            except Exception as build_error:  # noqa: BLE001 - try the next provider
                last_error = build_error
                continue
            try:
                async for event in delegate.stream_response(
                    system_instructions,
                    input,
                    model_settings,
                    tools,
                    output_schema,
                    handoffs,
                    tracing,
                    previous_response_id=previous_response_id,
                    conversation_id=conversation_id,
                    prompt=prompt,
                ):
                    started = True
                    yield event
            except Exception as exc:
                if _classify_error(exc) is None or started:
                    raise
                last_error = exc
                self._note_failure(index, exc)
                continue
            self._note_success(index)
            return
        if last_error is not None:
            raise last_error
        raise RuntimeError(
            "every LLM provider in the configured chain is exhausted "
            "(rate limit / quota); resume with 'strix --resume <run-name>' "
            "once a limit clears"
        )

    def get_retry_advice(self, request: ModelRetryAdviceRequest) -> ModelRetryAdvice | None:
        for index in self._candidate_indexes():
            entry = self._entries[index]
            if entry.model is not None:
                return entry.model.get_retry_advice(request)
        return None

    async def close(self) -> None:
        for entry in self._entries:
            if entry.model is None:
                continue
            try:
                await entry.model.close()
            except Exception:  # noqa: BLE001 - closing must not break shutdown
                logger.debug("closing provider %s failed", entry.label, exc_info=True)


# ---- wiring --------------------------------------------------------------------


def _default_delegate_builder(spec: LlmFallback) -> Model:
    """Build one backup provider's model bound to its own credentials.

    Imported lazily: ``strix.config.models`` imports this module at startup.
    """
    from strix.config.models import StrixProvider

    return StrixProvider(
        api_key=spec.api_key,
        base_url=spec.api_base,
        enable_failover=False,
    ).get_model(spec.model)


def _primary_spec(model_name: str, llm: LlmSettings) -> tuple[LlmFallback, str]:
    """Identity spec + display label for the pre-built primary model."""
    spec = LlmFallback(
        model=model_name or llm.model or "unknown",
        api_key=llm.api_key,
        api_base=llm.api_base,
    )
    return spec, spec.display_name()


def wrap_with_failover(
    primary: Model,
    *,
    model_name: str,
    llm: LlmSettings,
    delegate_builder: Callable[[LlmFallback], Model] | None = None,
) -> Model:
    """Return ``primary`` wrapped in the chain, or unchanged when no backup exists.

    ``delegate_builder`` is a seam for tests; production uses
    :func:`_default_delegate_builder`, so a wrapped model still reads settings
    fresh for each backup instead of touching the network at wrap time.
    """
    fallbacks = llm.fallbacks
    if not fallbacks:
        return primary
    spec, label = _primary_spec(model_name, llm)
    return FailoverModel(
        primary,
        primary_label=label,
        primary_key=_provider_key(spec),
        fallbacks=fallbacks,
        delegate_builder=delegate_builder or _default_delegate_builder,
    )


def describe_failover_chain() -> str | None:
    """One-line summary of the configured chain for scan-stop log messages."""
    from strix.config.loader import load_settings

    llm = load_settings().llm
    if not llm.fallbacks:
        return None
    names = [llm.model or "unknown", *(spec.display_name() for spec in llm.fallbacks)]
    return "chain: " + " -> ".join(names)
