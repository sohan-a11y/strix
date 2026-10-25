"""Sticky provider-chain failover: switching, config persistence, wiring."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from agents.items import ModelResponse, TResponseStreamEvent
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelTracing
from agents.retry import (
    ModelRetryAdvice,
    ModelRetryAdviceRequest,
)
from agents.usage import Usage
from openai import AuthenticationError, RateLimitError

from strix.config import loader
from strix.config.models import StrixProvider, configure_sdk_model_defaults
from strix.config.settings import LlmFallback, LlmSettings
from strix.llm import provider_chain
from strix.llm.provider_chain import (
    FAIL_STREAK_THRESHOLD,
    FailoverModel,
    add_provider_switch_listener,
    reset_failover_state,
    wrap_with_failover,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

    from agents.agent_output import AgentOutputSchemaBase
    from agents.handoffs import Handoff
    from agents.tool import Tool
    from openai.types.responses.response_prompt_param import ResponsePromptParam

    from strix.config.settings import Settings


_FALLBACK = LlmFallback(
    model="gemini/gemini-2.5-flash",
    api_key="cfg-gemini-key",
    label="gemini free",
)
_FALLBACK_TWO = LlmFallback(model="groq/llama-3.3-70b-versatile", api_key="cfg-groq-key")


class _StubModel(Model):
    """Model double: a script of outcomes per get_response/stream_response call."""

    def __init__(self, name: str, outcomes: list[Any]) -> None:
        self.name = name
        self.outcomes = outcomes
        self.calls = 0
        self.closed = False

    async def get_response(
        self,
        _system_instructions: str | None,
        _input: str | list[Any],
        _model_settings: ModelSettings,
        _tools: list[Tool],
        _output_schema: AgentOutputSchemaBase | None,
        _handoffs: list[Handoff],
        _tracing: ModelTracing,
        *,
        previous_response_id: str | None,  # noqa: ARG002 - stub signature parity
        conversation_id: str | None,  # noqa: ARG002 - stub signature parity
        prompt: ResponsePromptParam | None,  # noqa: ARG002 - stub signature parity
    ) -> ModelResponse:
        self.calls += 1
        outcome = self.outcomes[min(self.calls - 1, len(self.outcomes) - 1)]
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, ModelResponse)
        return outcome

    async def stream_response(
        self,
        _system_instructions: str | None,
        _input: str | list[Any],
        _model_settings: ModelSettings,
        _tools: list[Tool],
        _output_schema: AgentOutputSchemaBase | None,
        _handoffs: list[Handoff],
        _tracing: ModelTracing,
        *,
        previous_response_id: str | None,  # noqa: ARG002 - stub signature parity
        conversation_id: str | None,  # noqa: ARG002 - stub signature parity
        prompt: ResponsePromptParam | None,  # noqa: ARG002 - stub signature parity
    ) -> AsyncIterator[TResponseStreamEvent]:
        self.calls += 1
        outcome = self.outcomes[min(self.calls - 1, len(self.outcomes) - 1)]
        if isinstance(outcome, BaseException):
            raise outcome
        for event in outcome:
            if isinstance(event, BaseException):
                raise event
            yield event

    def get_retry_advice(self, request: ModelRetryAdviceRequest) -> ModelRetryAdvice | None:
        return ModelRetryAdvice(reason=f"advice-from-{self.name}:{request.attempt}")

    async def close(self) -> None:
        self.closed = True


def _response(name: str = "resp") -> ModelResponse:
    return ModelResponse(output=[], usage=Usage(), response_id=name)


def _rate_limit() -> RateLimitError:
    request = httpx.Request("GET", "https://providers.example.com/v1")
    response = httpx.Response(429, request=request)
    return RateLimitError("429 too many requests", response=response, body=None)


def _auth_error() -> AuthenticationError:
    request = httpx.Request("GET", "https://providers.example.com/v1")
    response = httpx.Response(401, request=request)
    return AuthenticationError("invalid key", response=response, body=None)


def _rate_limits(count: int) -> list[RateLimitError]:
    return [_rate_limit() for _ in range(count)]


def _model_settings_stub() -> ModelSettings:
    return ModelSettings()


async def _call(model: FailoverModel) -> ModelResponse:
    return await model.get_response(
        None,
        "ping",
        _model_settings_stub(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


async def _stream(model: FailoverModel) -> AsyncIterator[TResponseStreamEvent]:
    return model.stream_response(
        None,
        "ping",
        _model_settings_stub(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


def _llm_settings(**overrides: Any) -> LlmSettings:
    """Build settings with field-name kwargs (populate_by_name)."""
    settings: LlmSettings = LlmSettings(**overrides)
    return settings


def _chain(
    primary_outcomes: list[Any],
    fallback_specs: tuple[LlmFallback, ...] = (_FALLBACK,),
    fallback_outcomes: list[Any] | None = None,
) -> tuple[FailoverModel, list[_StubModel]]:
    """Build a FailoverModel with stub delegates through the public wrap seam.

    The returned ``stubs`` list stays connected to the lazy builder, so
    fallback delegates appear on it only once a cascade reached them. Each
    element of ``fallback_outcomes`` is ONE call's outcome (a ModelResponse for
    get_response, an event list for stream_response, an exception to raise).
    """
    primary = _StubModel("primary", primary_outcomes)
    stubs: list[_StubModel] = [primary]
    scripted = iter(fallback_outcomes or [])

    def builder(spec: LlmFallback) -> Model:
        stub = _StubModel(f"stub-{spec.model}", [next(scripted, _response())])
        stubs.append(stub)
        return stub

    llm = _llm_settings(
        model="openrouter/z-ai/glm-5.3",
        api_key="sk-primary",
        fallbacks=list(fallback_specs),
    )
    wrapped = wrap_with_failover(
        primary,
        model_name="openrouter/z-ai/glm-5.3",
        llm=llm,
        delegate_builder=builder,
    )
    assert isinstance(wrapped, FailoverModel)
    return wrapped, stubs


@pytest.fixture(autouse=True)
def _fresh_chain_state() -> Iterator[None]:
    reset_failover_state()
    yield
    reset_failover_state()


# --------------------------------------------------------------------------- #
# switching behavior
# --------------------------------------------------------------------------- #


async def test_primary_served_no_fallback() -> None:
    model, stubs = _chain([_response("primary")])
    response = await _call(model)
    assert response.response_id == "primary"
    assert [stub.calls for stub in stubs] == [1]  # no fallback built


async def test_one_rate_limit_falls_over_within_the_call() -> None:
    model, stubs = _chain([_rate_limit()], fallback_outcomes=[_response()])
    response = await _call(model)
    assert response.response_id == "resp"
    assert [stub.calls for stub in stubs] == [1, 1]


async def test_transient_blip_returns_to_primary_next_call() -> None:
    model, stubs = _chain([_rate_limit(), _response("primary")])
    await _call(model)
    second = await _call(model)
    assert second.response_id == "primary"
    assert [stub.calls for stub in stubs] == [2, 1]


async def test_streak_threshold_makes_the_switch_sticky() -> None:
    model, stubs = _chain([*_rate_limits(FAIL_STREAK_THRESHOLD)])
    for _ in range(FAIL_STREAK_THRESHOLD):
        await _call(model)
    later = await _call(model)
    assert later.response_id == "resp"
    # Primary stops being probed once marked exhausted.
    assert stubs[0].calls == FAIL_STREAK_THRESHOLD
    assert stubs[1].calls >= 1


async def test_auth_error_exhausts_immediately() -> None:
    model, stubs = _chain([_auth_error(), _response("primary")])
    first = await _call(model)
    assert first.response_id == "resp"
    later = await _call(model)
    assert later.response_id == "resp"
    assert stubs[0].calls == 1


async def test_unclassified_errors_are_not_failover_material() -> None:
    model, stubs = _chain([ValueError("bad request shape")])
    with pytest.raises(ValueError, match="bad request shape"):
        await _call(model)
    assert [stub.calls for stub in stubs] == [1]


async def test_chain_exhausted_raises_last_provider_error() -> None:
    model, stubs = _chain(
        [_rate_limit()],
        fallback_specs=(_FALLBACK, _FALLBACK_TWO),
        fallback_outcomes=[_rate_limit(), _rate_limit()],
    )
    with pytest.raises(RateLimitError):
        await _call(model)
    assert all(stub.calls == 1 for stub in stubs)


async def test_streak_decay_keeps_old_blips_out_of_the_streak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model, stubs = _chain([*_rate_limits(2), _response("primary"), _response("primary")])
    stamps: list[float] = [0.0]

    def fake_monotonic() -> float:
        stamps.append(stamps[-1] + 400.0)
        return stamps[-1]

    monkeypatch.setattr(provider_chain, "time", SimpleNamespace(monotonic=fake_monotonic))
    for _ in range(4):
        await _call(model)
    assert stubs[0].calls == 4  # never marked dead: blips were 400s apart
    assert stubs[1].calls == 2  # the two blips still fell over


async def test_stream_falls_over_before_first_event() -> None:
    model, stubs = _chain([_rate_limit()], fallback_outcomes=[["event-1", "event-2"]])
    iterator = await _stream(model)
    events: list[Any] = [event async for event in iterator]
    assert list(events) == ["event-1", "event-2"]
    assert [stub.calls for stub in stubs] == [1, 1]


async def test_stream_partial_then_rate_limit_raises() -> None:
    model, stubs = _chain([["event-1", _rate_limit()]])
    iterator = await _stream(model)
    consumed: list[Any] = []
    with pytest.raises(RateLimitError):
        async for event in iterator:
            consumed.append(event)
    assert consumed == ["event-1"]
    assert [stub.calls for stub in stubs] == [1]


def test_retry_advice_flows_from_the_active_delegate() -> None:
    model, _ = _chain([_response("primary")])
    fallback = _StubModel("fallback", [_response()])
    model._entries[1].model = fallback
    provider_chain._record_immediate_failure(
        model._entries[0].key,
        "test exhaustion",
    )
    advice = model.get_retry_advice(
        ModelRetryAdviceRequest(error=ValueError("x"), attempt=1, stream=False)
    )
    assert advice is not None
    assert advice.reason is not None
    assert "advice-from-fallback" in advice.reason


async def test_close_closes_built_delegates() -> None:
    model, stubs = _chain([_rate_limit()])  # one blip builds the fallback
    await _call(model)
    assert len(stubs) == 2
    await model.close()
    assert all(stub.closed for stub in stubs)


# --------------------------------------------------------------------------- #
# notifications + configuration seams
# --------------------------------------------------------------------------- #


async def test_switch_listener_fires_once_at_exhaustion() -> None:
    seen: list[tuple[str, str, str]] = []
    unsubscribe = add_provider_switch_listener(
        lambda from_label, to_label, reason: seen.append((from_label, to_label, reason))
    )
    try:
        model, _ = _chain([*_rate_limits(FAIL_STREAK_THRESHOLD)])
        for _ in range(FAIL_STREAK_THRESHOLD):
            await _call(model)
        assert len(seen) == 1
        assert seen[0][0] == "openrouter/z-ai/glm-5.3"
        assert seen[0][1] == "gemini free"
        assert "rate limit" in seen[0][2]
    finally:
        unsubscribe()


async def test_broken_listener_never_breaks_the_scan() -> None:
    add_provider_switch_listener(_boom_listener)
    model, _ = _chain([*_rate_limits(FAIL_STREAK_THRESHOLD)])
    response = await _call(model)
    assert response.response_id == "resp"


def _boom_listener(*_args: Any) -> None:
    raise RuntimeError("listener broken on purpose")


def test_wrap_without_fallbacks_is_identity() -> None:
    primary = _StubModel("primary", [_response("primary")])
    llm = _llm_settings(model="openai/gpt-5.4")
    assert wrap_with_failover(primary, model_name="openai/gpt-5.4", llm=llm) is primary


# --------------------------------------------------------------------------- #
# settings + config-file persistence
# --------------------------------------------------------------------------- #


def test_fallback_list_parses_from_json_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "STRIX_FALLBACK_LLMS",
        json.dumps(
            [
                {"model": "gemini/gemini-2.5-flash", "api_key": "k1"},
                {"model": "groq/llama-3.3-70b-versatile", "api_key": "k2"},
            ]
        ),
    )
    settings = LlmSettings()
    assert [spec.model for spec in settings.fallbacks] == [
        "gemini/gemini-2.5-flash",
        "groq/llama-3.3-70b-versatile",
    ]


def test_config_file_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override = tmp_path / "cli-config.json"
    override.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(loader, "_override", override)
    monkeypatch.setattr(loader, "_cached", None)

    entries = [
        {"model": "gemini/gemini-2.5-flash", "api_key": "k1", "label": "gemini free"},
    ]
    loader.save_llm_fallbacks(entries)
    monkeypatch.setattr(loader, "_cached", None)
    settings = loader.load_settings()
    assert [spec.display_name() for spec in settings.llm.fallbacks] == ["gemini free"]
    assert settings.llm.fallbacks[0].api_key == "k1"

    loader.save_llm_fallbacks([])
    monkeypatch.setattr(loader, "_cached", None)
    assert loader.load_settings().llm.fallbacks == []


def test_get_model_wraps_when_a_chain_is_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override = tmp_path / "cli-config.json"
    override.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(loader, "_override", override)
    monkeypatch.setenv("STRIX_LLM", "openrouter/z-ai/glm-5.3")
    monkeypatch.setenv("LLM_API_KEY", "sk-primary")
    monkeypatch.setenv(
        "STRIX_FALLBACK_LLMS",
        json.dumps([{"model": "gemini/gemini-2.5-flash", "api_key": "k1"}]),
    )
    monkeypatch.setattr(loader, "_cached", None)
    settings: Settings = loader.load_settings()
    configure_sdk_model_defaults(settings)

    wrapped = StrixProvider().get_model("openrouter/z-ai/glm-5.3")
    assert isinstance(wrapped, FailoverModel)
    assert wrapped._entries[0].label == "openrouter/z-ai/glm-5.3"
    assert wrapped._entries[1].label == "gemini/gemini-2.5-flash"
