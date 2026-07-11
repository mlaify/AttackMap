from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from attackmap.llm_review import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    OPENAI_DEFAULT_MODEL,
    LlmReviewError,
    generate_llm_review,
)
from attackmap.models import AttackPath, AttackSurface, Finding, Route, ScanResult


@dataclass
class _FakeBlock:
    type: str
    text: str = ""


@dataclass
class _FakeUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class _FakeMessage:
    content: list[_FakeBlock]
    usage: _FakeUsage = field(default_factory=_FakeUsage)
    stop_reason: str | None = "end_turn"


class _FakeStreamContext:
    def __init__(self, message: _FakeMessage) -> None:
        self._message = message

    def __enter__(self) -> "_FakeStreamContext":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def get_final_message(self) -> _FakeMessage:
        return self._message


class _FakeMessages:
    def __init__(self, message: _FakeMessage, captured: dict[str, Any], endpoint: str) -> None:
        self._message = message
        self._captured = captured
        self._endpoint = endpoint

    def stream(self, **kwargs: Any) -> _FakeStreamContext:
        self._captured.update(kwargs)
        self._captured["endpoint"] = self._endpoint
        return _FakeStreamContext(self._message)


class _FakeBeta:
    def __init__(self, message: _FakeMessage, captured: dict[str, Any]) -> None:
        self.messages = _FakeMessages(message, captured, endpoint="beta")


class _FakeClient:
    def __init__(self, message: _FakeMessage) -> None:
        self.captured: dict[str, Any] = {}
        self.messages = _FakeMessages(message, self.captured, endpoint="standard")
        self.beta = _FakeBeta(message, self.captured)


def _trivial_scan() -> ScanResult:
    return ScanResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/login", method="POST", file="app/auth.py")],
        files_scanned=1,
    )


def _surfaces() -> list[AttackSurface]:
    return [
        AttackSurface(
            route="/login",
            method="POST",
            file="app/auth.py",
            category="auth",
            exposure="public",
            risk="high",
        )
    ]


def _findings() -> list[Finding]:
    return [
        Finding(
            title="Auth endpoint present",
            severity="medium",
            evidence=["POST /login"],
            mitigation="Verify rate limiting.",
            confidence="medium",
        )
    ]


def test_generate_llm_review_returns_markdown_and_passes_expected_kwargs() -> None:
    fake_message = _FakeMessage(
        content=[
            _FakeBlock(type="thinking"),
            _FakeBlock(type="text", text="# Defensive Review\n\nBody."),
        ],
        usage=_FakeUsage(input_tokens=1234, output_tokens=567, cache_read_input_tokens=42),
    )
    client = _FakeClient(fake_message)

    result = generate_llm_review(
        _trivial_scan(),
        _surfaces(),
        _findings(),
        [],
        client=client,
    )

    assert result.markdown == "# Defensive Review\n\nBody."
    assert result.model == DEFAULT_MODEL
    assert result.usage["input_tokens"] == 1234
    assert result.usage["output_tokens"] == 567
    assert result.usage["cache_read_input_tokens"] == 42
    assert result.stop_reason == "end_turn"

    captured = client.captured
    assert captured["model"] == DEFAULT_MODEL
    assert captured["max_tokens"] == DEFAULT_MAX_TOKENS
    assert captured["thinking"] == {"type": "adaptive"}
    assert captured["output_config"] == {"effort": "high"}
    system_blocks = captured["system"]
    assert isinstance(system_blocks, list) and len(system_blocks) == 1
    assert system_blocks[0]["cache_control"] == {"type": "ephemeral"}
    assert "AttackMap Review Analyst" in system_blocks[0]["text"]
    user_messages = captured["messages"]
    assert user_messages[0]["role"] == "user"
    assert "Evidence pack (JSON)" in user_messages[0]["content"]


def test_generate_llm_review_honors_model_and_effort_overrides() -> None:
    fake_message = _FakeMessage(content=[_FakeBlock(type="text", text="hi")])
    client = _FakeClient(fake_message)

    generate_llm_review(
        _trivial_scan(),
        _surfaces(),
        _findings(),
        [],
        model="claude-sonnet-4-6",
        effort="xhigh",
        max_tokens=1024,
        client=client,
    )

    captured = client.captured
    assert captured["model"] == "claude-sonnet-4-6"
    assert captured["output_config"] == {"effort": "xhigh"}
    assert captured["max_tokens"] == 1024


def test_default_model_is_opus_4_8() -> None:
    assert DEFAULT_MODEL == "claude-opus-4-8"


def test_fast_mode_uses_beta_endpoint_on_supported_model() -> None:
    client = _FakeClient(_FakeMessage(content=[_FakeBlock(type="text", text="hi")]))

    generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        model="claude-opus-4-8", client=client, speed="fast",
    )

    captured = client.captured
    assert captured["endpoint"] == "beta"
    assert captured["speed"] == "fast"
    assert captured["betas"] == ["fast-mode-2026-02-01"]


def test_fast_mode_falls_back_to_standard_on_unsupported_model() -> None:
    client = _FakeClient(_FakeMessage(content=[_FakeBlock(type="text", text="hi")]))

    generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        model="claude-sonnet-5", client=client, speed="fast",
    )

    captured = client.captured
    assert captured["endpoint"] == "standard"
    assert "speed" not in captured
    assert "betas" not in captured


def test_standard_speed_uses_standard_endpoint() -> None:
    client = _FakeClient(_FakeMessage(content=[_FakeBlock(type="text", text="hi")]))

    generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        model="claude-opus-4-8", client=client,  # speed defaults to standard
    )

    assert client.captured["endpoint"] == "standard"
    assert "speed" not in client.captured


def test_generate_llm_review_raises_when_no_text_blocks_returned() -> None:
    client = _FakeClient(_FakeMessage(content=[_FakeBlock(type="thinking")]))

    with pytest.raises(LlmReviewError, match="no text content"):
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], client=client)


def test_generate_llm_review_raises_clear_error_without_api_key(monkeypatch) -> None:
    # Force the SDK-resolution path with backend=api so we don't fall through to CLI.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)

    with pytest.raises(LlmReviewError) as excinfo:
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], backend="api")

    message = str(excinfo.value)
    # Either the SDK is missing or the key is missing — both are user-actionable.
    assert (
        "ANTHROPIC_API_KEY" in message
        or "anthropic SDK is not installed" in message
        or "No API credentials" in message
    )


def test_generate_llm_review_uses_auth_token_when_api_key_is_absent(monkeypatch) -> None:
    """ANTHROPIC_AUTH_TOKEN should produce an SDK client built with auth_token=, not api_key=."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "oauth-bearer-xyz")

    captured_constructor_kwargs: dict[str, Any] = {}
    fake_message = _FakeMessage(content=[_FakeBlock(type="text", text="ok")])

    class _FakeAnthropicModule:
        @staticmethod
        def Anthropic(**kwargs):  # noqa: N802 (matches SDK class name)
            captured_constructor_kwargs.update(kwargs)
            return _FakeClient(fake_message)

    import sys

    monkeypatch.setitem(sys.modules, "anthropic", _FakeAnthropicModule)

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [], backend="api"
    )

    assert result.backend == "api"
    assert captured_constructor_kwargs == {"auth_token": "oauth-bearer-xyz"}


# ---------- Claude CLI backend tests ----------


def _make_cli_runner(stdout: str, *, returncode: int = 0, stderr: str = ""):
    captured: dict[str, Any] = {}

    class _FakeCompleted:
        def __init__(self) -> None:
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def _runner(cmd: list[str], stdin_text: str) -> _FakeCompleted:
        captured["cmd"] = cmd
        captured["stdin"] = stdin_text
        return _FakeCompleted()

    return _runner, captured


def test_cli_backend_parses_result_field_and_passes_correct_flags() -> None:
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": "# Review\n\nNarrative body.",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 12, "output_tokens": 34},
        "modelUsage": {"claude-opus-4-7[1m]": {"inputTokens": 12}},
    }
    runner, captured = _make_cli_runner(json.dumps(payload))

    result = generate_llm_review(
        _trivial_scan(),
        _surfaces(),
        _findings(),
        [],
        backend="cli",
        cli_runner=runner,
    )

    assert result.backend == "cli"
    assert result.markdown == "# Review\n\nNarrative body."
    assert result.stop_reason == "end_turn"
    assert result.usage["input_tokens"] == 12
    assert result.model == "claude-opus-4-7[1m]"

    cmd = captured["cmd"]
    assert cmd[0:3] == ["claude", "-p", "--output-format=json"]
    assert "--model" in cmd
    assert "--system-prompt" in cmd
    sys_idx = cmd.index("--system-prompt")
    assert "AttackMap Review Analyst" in cmd[sys_idx + 1]
    assert "Evidence pack (JSON)" in captured["stdin"]


def test_cli_backend_raises_when_payload_marks_error() -> None:
    payload = {
        "type": "result",
        "subtype": "error_max_budget_usd",
        "is_error": True,
        "errors": ["Reached maximum budget ($0.01)"],
    }
    runner, _ = _make_cli_runner(json.dumps(payload))

    with pytest.raises(LlmReviewError, match="Reached maximum budget"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [], backend="cli", cli_runner=runner
        )


def test_cli_backend_not_logged_in_surfaces_login_hint() -> None:
    """The real `claude` CLI returns is_error=true with subtype="success"
    and the human message in `result` when the user isn't logged in.
    Historically we printed the misleading "success" subtype; make sure
    we now surface the real message and a login hint."""
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": True,
        "result": "Not logged in · Please run /login",
    }
    runner, _ = _make_cli_runner(json.dumps(payload))
    with pytest.raises(LlmReviewError) as excinfo:
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [], backend="cli", cli_runner=runner
        )
    msg = str(excinfo.value)
    assert "Not logged in" in msg
    assert "success" not in msg  # never surface the misleading subtype
    assert "claude login" in msg or "/login" in msg


def test_cli_backend_prefers_result_text_over_subtype() -> None:
    """When is_error=true and both `result` and `subtype` are present,
    the human-readable `result` text wins."""
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": True,
        "result": "Rate limit hit, try again in 60s",
    }
    runner, _ = _make_cli_runner(json.dumps(payload))
    with pytest.raises(LlmReviewError, match="Rate limit hit"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [], backend="cli", cli_runner=runner
        )


def test_cli_backend_raises_when_stdout_is_not_json() -> None:
    runner, _ = _make_cli_runner("not json at all")
    with pytest.raises(LlmReviewError, match="non-JSON output"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [], backend="cli", cli_runner=runner
        )


def test_cli_backend_raises_when_subprocess_exits_nonzero_without_stdout() -> None:
    runner, _ = _make_cli_runner("", returncode=2, stderr="boom")
    with pytest.raises(LlmReviewError, match="exited with status 2"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [], backend="cli", cli_runner=runner
        )


# ---------- Backend resolution tests ----------


def test_auto_backend_picks_api_when_api_key_present(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    fake_message = _FakeMessage(content=[_FakeBlock(type="text", text="ok")])

    class _FakeAnthropicModule:
        @staticmethod
        def Anthropic(**kwargs):  # noqa: N802
            return _FakeClient(fake_message)

    import sys

    monkeypatch.setitem(sys.modules, "anthropic", _FakeAnthropicModule)

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [], backend="auto"
    )
    assert result.backend == "api"


def test_auto_backend_falls_back_to_cli_when_no_creds(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr("attackmap.llm_review._claude_cli_available", lambda: True)

    payload = {"type": "result", "is_error": False, "result": "hi"}
    runner, _ = _make_cli_runner(json.dumps(payload))

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [], backend="auto", cli_runner=runner
    )
    assert result.backend == "cli"


def test_auto_backend_falls_back_to_cli_when_key_set_but_sdk_missing(monkeypatch) -> None:
    # Homebrew installs attackmap without the anthropic SDK. A key set in that
    # environment must fall back to the `claude` CLI, not error.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr("attackmap.llm_review._anthropic_sdk_available", lambda: False)
    monkeypatch.setattr("attackmap.llm_review._claude_cli_available", lambda: True)

    payload = {"type": "result", "is_error": False, "result": "hi"}
    runner, _ = _make_cli_runner(json.dumps(payload))

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [], backend="auto", cli_runner=runner
    )
    assert result.backend == "cli"


def test_openai_auto_falls_back_to_codex_when_key_set_but_sdk_missing(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.setattr("attackmap.llm_review._openai_sdk_available", lambda: False)
    monkeypatch.setattr("attackmap.llm_review._codex_cli_available", lambda: True)
    runner, _ = _make_cli_runner("hi")

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        provider="openai", backend="auto", codex_runner=runner,
    )
    assert result.backend == "cli"


def test_auto_backend_raises_when_no_creds_and_no_cli(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr("attackmap.llm_review._claude_cli_available", lambda: False)

    with pytest.raises(LlmReviewError, match="No LLM backend available"):
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], backend="auto")


def test_explicit_cli_backend_raises_when_cli_missing(monkeypatch) -> None:
    monkeypatch.setattr("attackmap.llm_review._claude_cli_available", lambda: False)
    with pytest.raises(LlmReviewError, match="--llm-backend cli.*not on PATH"):
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], backend="cli")


# ---------- OpenAI / Codex provider tests ----------


@dataclass
class _FakeOpenAIUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class _FakeOpenAIResponse:
    output_text: str
    model: str = OPENAI_DEFAULT_MODEL
    status: str = "completed"
    usage: _FakeOpenAIUsage = field(default_factory=_FakeOpenAIUsage)


class _FakeResponses:
    def __init__(self, response: _FakeOpenAIResponse, captured: dict[str, Any]) -> None:
        self._response = response
        self._captured = captured

    def create(self, **kwargs: Any) -> _FakeOpenAIResponse:
        self._captured.update(kwargs)
        return self._response


class _FakeOpenAIClient:
    def __init__(self, response: _FakeOpenAIResponse) -> None:
        self.captured: dict[str, Any] = {}
        self.responses = _FakeResponses(response, self.captured)


def test_openai_default_model_constant() -> None:
    assert OPENAI_DEFAULT_MODEL == "gpt-5-codex"


def test_openai_api_returns_markdown_and_passes_expected_kwargs() -> None:
    response = _FakeOpenAIResponse(
        output_text="# Defensive Review\n\nBody.",
        usage=_FakeOpenAIUsage(input_tokens=100, output_tokens=200),
    )
    client = _FakeOpenAIClient(response)

    result = generate_llm_review(
        _trivial_scan(),
        _surfaces(),
        _findings(),
        [],
        provider="openai",
        openai_client=client,
    )

    assert result.backend == "api"
    assert result.markdown == "# Defensive Review\n\nBody."
    assert result.model == OPENAI_DEFAULT_MODEL
    assert result.stop_reason == "completed"
    assert result.usage == {"input_tokens": 100, "output_tokens": 200}

    captured = client.captured
    assert captured["model"] == OPENAI_DEFAULT_MODEL
    assert captured["reasoning"] == {"effort": "high"}
    assert captured["max_output_tokens"] == DEFAULT_MAX_TOKENS
    assert "AttackMap Review Analyst" in captured["instructions"]
    assert "Evidence pack (JSON)" in captured["input"]


def test_openai_passes_model_through_verbatim() -> None:
    client = _FakeOpenAIClient(_FakeOpenAIResponse(output_text="hi", model="gpt-5.5"))

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        provider="openai", openai_client=client, model="gpt-5.5",
    )

    assert client.captured["model"] == "gpt-5.5"
    assert result.model == "gpt-5.5"


def test_openai_effort_clamps_beyond_high() -> None:
    client = _FakeOpenAIClient(_FakeOpenAIResponse(output_text="hi"))

    generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        provider="openai", openai_client=client, effort="max",
    )

    assert client.captured["reasoning"] == {"effort": "high"}


def test_openai_raises_when_no_text_returned() -> None:
    client = _FakeOpenAIClient(_FakeOpenAIResponse(output_text=""))

    with pytest.raises(LlmReviewError, match="no text content"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [],
            provider="openai", openai_client=client,
        )


def test_openai_auto_backend_picks_api_when_client_present() -> None:
    client = _FakeOpenAIClient(_FakeOpenAIResponse(output_text="ok"))
    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        provider="openai", backend="auto", openai_client=client,
    )
    assert result.backend == "api"


def test_openai_api_no_key_raises(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LlmReviewError) as excinfo:
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [],
            provider="openai", backend="api",
        )
    message = str(excinfo.value)
    assert "OPENAI_API_KEY" in message or "openai SDK is not installed" in message


def test_openai_api_builds_client_with_key_from_env(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    captured_ctor: dict[str, Any] = {}
    response = _FakeOpenAIResponse(output_text="ok")

    class _FakeOpenAIModule:
        @staticmethod
        def OpenAI(**kwargs):  # noqa: N802 (matches SDK class name)
            captured_ctor.update(kwargs)
            return _FakeOpenAIClient(response)

    import sys

    monkeypatch.setitem(sys.modules, "openai", _FakeOpenAIModule)

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        provider="openai", backend="api",
    )

    assert result.backend == "api"
    assert captured_ctor["api_key"] == "sk-openai-test"
    assert "timeout" in captured_ctor


# ---------- Codex CLI backend tests ----------


def test_codex_cli_backend_reads_stdout_and_passes_correct_flags() -> None:
    runner, captured = _make_cli_runner("# Review\n\nCodex narrative body.")

    result = generate_llm_review(
        _trivial_scan(),
        _surfaces(),
        _findings(),
        [],
        provider="openai",
        backend="cli",
        codex_runner=runner,
    )

    assert result.backend == "cli"
    assert result.markdown == "# Review\n\nCodex narrative body."
    assert result.model == OPENAI_DEFAULT_MODEL

    cmd = captured["cmd"]
    assert cmd[0:2] == ["codex", "exec"]
    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == OPENAI_DEFAULT_MODEL
    assert "-c" in cmd
    assert cmd[cmd.index("-c") + 1] == 'model_reasoning_effort="high"'
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert "--skip-git-repo-check" in cmd
    # The rendered system prompt is the final positional argument (the
    # instruction); the evidence pack is piped in on stdin as context.
    assert "AttackMap Review Analyst" in cmd[-1]
    assert "Evidence pack (JSON)" in captured["stdin"]


def test_codex_cli_backend_raises_on_nonzero_exit() -> None:
    runner, _ = _make_cli_runner("", returncode=2, stderr="boom")
    with pytest.raises(LlmReviewError, match="exited with status 2"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [],
            provider="openai", backend="cli", codex_runner=runner,
        )


def test_codex_cli_login_error_surfaces_hint() -> None:
    runner, _ = _make_cli_runner("", returncode=1, stderr="Error: not logged in")
    with pytest.raises(LlmReviewError) as excinfo:
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [],
            provider="openai", backend="cli", codex_runner=runner,
        )
    assert "codex login" in str(excinfo.value)


def test_openai_auto_backend_falls_back_to_codex_when_no_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("attackmap.llm_review._codex_cli_available", lambda: True)
    runner, _ = _make_cli_runner("hi")

    result = generate_llm_review(
        _trivial_scan(), _surfaces(), _findings(), [],
        provider="openai", backend="auto", codex_runner=runner,
    )
    assert result.backend == "cli"


def test_openai_auto_raises_when_no_key_and_no_codex(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("attackmap.llm_review._codex_cli_available", lambda: False)
    with pytest.raises(LlmReviewError, match="No OpenAI backend available"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [],
            provider="openai", backend="auto",
        )


def test_explicit_codex_backend_raises_when_cli_missing(monkeypatch) -> None:
    monkeypatch.setattr("attackmap.llm_review._codex_cli_available", lambda: False)
    with pytest.raises(LlmReviewError, match="--llm-backend cli.*not on PATH"):
        generate_llm_review(
            _trivial_scan(), _surfaces(), _findings(), [],
            provider="openai", backend="cli",
        )
