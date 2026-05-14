from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from attackmap.llm_review import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
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
    def __init__(self, message: _FakeMessage, captured: dict[str, Any]) -> None:
        self._message = message
        self._captured = captured

    def stream(self, **kwargs: Any) -> _FakeStreamContext:
        self._captured.update(kwargs)
        return _FakeStreamContext(self._message)


class _FakeClient:
    def __init__(self, message: _FakeMessage) -> None:
        self.captured: dict[str, Any] = {}
        self.messages = _FakeMessages(message, self.captured)


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
