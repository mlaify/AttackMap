"""Anthropic-powered narrative review generator.

Wraps the existing prompt scaffolding (`review_prompts.render_review_prompts`)
in a real Claude call so users can produce a story-bearing defensive review
without copy-pasting JSON into a chat client.

Auth resolution (in order):
  1. Explicit `client=` (tests / programmatic override)
  2. `ANTHROPIC_API_KEY` env  → SDK with api_key  (per-token API billing)
  3. `ANTHROPIC_AUTH_TOKEN` env → SDK with auth_token (OAuth bearer)
  4. `claude` CLI on PATH      → shell out to `claude -p --output-format=json`
                                 (uses whatever auth `claude login` configured —
                                 typically the user's Pro/Max subscription)

The user can force a backend via the `backend` argument or the CLI's
`--llm-backend` flag; "auto" walks the order above and picks the first one
that resolves.

Optional dependency: `pip install attackmap[llm]` installs the anthropic SDK.
The CLI backend only requires the `claude` binary on PATH (no SDK install).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Literal

from .models import AttackPath, AttackSurface, Finding, ScanResult
from .review_prompts import render_review_prompts

DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "high"
DEFAULT_MAX_TOKENS = 32000
CLAUDE_CLI_TIMEOUT_SECONDS = 600

LlmBackend = Literal["auto", "api", "cli"]


class LlmReviewError(RuntimeError):
    """Raised when the LLM-backed review cannot be produced."""


@dataclass(frozen=True)
class LlmReviewResult:
    markdown: str
    model: str
    stop_reason: str | None
    usage: dict[str, int]
    backend: Literal["api", "cli"]


# ---------- Auth + SDK backend ----------


def _resolve_sdk_client(api_key: str | None, client: Any | None) -> tuple[Any, str]:
    """Return (anthropic client, auth_kind). auth_kind ∈ {'api_key', 'auth_token'}."""
    if client is not None:
        return client, "explicit"
    try:
        import anthropic
    except ImportError as exc:
        raise LlmReviewError(
            "The anthropic SDK is not installed. Install with `pip install attackmap[llm]` "
            "to use the API backend, or ensure the `claude` CLI is on PATH for the CLI backend."
        ) from exc

    resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if resolved_key:
        return anthropic.Anthropic(api_key=resolved_key), "api_key"

    auth_token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
    if auth_token:
        return anthropic.Anthropic(auth_token=auth_token), "auth_token"

    raise LlmReviewError(
        "No API credentials found. Set ANTHROPIC_API_KEY (per-token API billing) or "
        "ANTHROPIC_AUTH_TOKEN (OAuth bearer), or install the `claude` CLI and run "
        "`claude login` to use your Claude subscription."
    )


def _extract_text(blocks: list[Any]) -> str:
    parts: list[str] = []
    for block in blocks:
        if getattr(block, "type", None) == "text":
            text = getattr(block, "text", "")
            if text:
                parts.append(text)
    return "\n".join(parts).strip()


def _usage_dict(usage: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for field in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        value = getattr(usage, field, None)
        if isinstance(value, int):
            out[field] = value
    return out


def _run_via_sdk(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    effort: str,
    max_tokens: int,
    api_key: str | None,
    client: Any | None,
) -> LlmReviewResult:
    sdk_client, _ = _resolve_sdk_client(api_key, client)

    request_kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": [
            {"type": "text", "text": rendered_system, "cache_control": {"type": "ephemeral"}}
        ],
        "messages": [{"role": "user", "content": rendered_user}],
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": effort},
    }

    try:
        with sdk_client.messages.stream(**request_kwargs) as stream:
            final_message = stream.get_final_message()
    except LlmReviewError:
        raise
    except Exception as exc:  # pragma: no cover - surface SDK errors verbatim
        raise LlmReviewError(f"Claude API call failed: {exc}") from exc

    markdown = _extract_text(getattr(final_message, "content", []) or [])
    if not markdown:
        raise LlmReviewError("Claude returned no text content for the review.")

    stop_reason = getattr(final_message, "stop_reason", None)
    return LlmReviewResult(
        markdown=markdown,
        model=model,
        stop_reason=stop_reason if isinstance(stop_reason, str) else None,
        usage=_usage_dict(getattr(final_message, "usage", None)),
        backend="api",
    )


# ---------- Claude CLI backend ----------


def _claude_cli_available() -> bool:
    return shutil.which("claude") is not None


def _run_via_claude_cli(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    runner: Any | None = None,
) -> LlmReviewResult:
    """Invoke `claude -p --output-format=json` and return the result.

    The `runner` argument is only used by tests to inject a fake subprocess
    runner; in production we go straight to subprocess.run.
    """
    if runner is None and not _claude_cli_available():
        raise LlmReviewError(
            "`claude` CLI was not found on PATH. Install Claude Code (https://claude.com/claude-code) "
            "and run `claude login`, or set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN to use the SDK backend."
        )

    cmd = [
        "claude",
        "-p",
        "--output-format=json",
        "--model",
        model,
        "--system-prompt",
        rendered_system,
    ]

    try:
        if runner is None:
            completed = subprocess.run(
                cmd,
                input=rendered_user,
                text=True,
                capture_output=True,
                check=False,
                timeout=CLAUDE_CLI_TIMEOUT_SECONDS,
            )
        else:
            completed = runner(cmd, rendered_user)
    except FileNotFoundError as exc:
        raise LlmReviewError("`claude` CLI was not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LlmReviewError(
            f"`claude` CLI did not respond within {CLAUDE_CLI_TIMEOUT_SECONDS}s."
        ) from exc

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0 and not stdout:
        raise LlmReviewError(
            f"`claude` CLI exited with status {completed.returncode}: {stderr or '<no stderr>'}"
        )
    if not stdout:
        raise LlmReviewError("`claude` CLI produced no output.")

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise LlmReviewError(
            f"`claude` CLI returned non-JSON output: {stdout[:200]}..."
        ) from exc

    if payload.get("is_error"):
        errors = payload.get("errors") or [payload.get("subtype") or "unknown error"]
        raise LlmReviewError(f"`claude` CLI reported an error: {'; '.join(str(e) for e in errors)}")

    markdown = payload.get("result")
    if not isinstance(markdown, str) or not markdown.strip():
        raise LlmReviewError("`claude` CLI returned no `result` text.")

    usage_payload = payload.get("usage") or {}
    usage: dict[str, int] = {}
    for field in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        value = usage_payload.get(field)
        if isinstance(value, int):
            usage[field] = value

    cli_model = model
    model_usage = payload.get("modelUsage")
    if isinstance(model_usage, dict) and model_usage:
        cli_model = next(iter(model_usage.keys()), model)

    stop_reason = payload.get("stop_reason")
    return LlmReviewResult(
        markdown=markdown.strip(),
        model=cli_model,
        stop_reason=stop_reason if isinstance(stop_reason, str) else None,
        usage=usage,
        backend="cli",
    )


# ---------- Public entry point ----------


def _resolve_backend(
    backend: LlmBackend,
    *,
    api_key: str | None,
    client: Any | None,
) -> Literal["api", "cli"]:
    if backend == "api":
        return "api"
    if backend == "cli":
        if not _claude_cli_available():
            raise LlmReviewError(
                "`--llm-backend cli` was requested but the `claude` CLI is not on PATH."
            )
        return "cli"
    # auto
    if client is not None or api_key:
        return "api"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "api"
    if _claude_cli_available():
        return "cli"
    raise LlmReviewError(
        "No LLM backend available. Set ANTHROPIC_API_KEY, set ANTHROPIC_AUTH_TOKEN, "
        "or install the `claude` CLI and run `claude login`."
    )


def generate_llm_review(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    *,
    model: str | None = None,
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    api_key: str | None = None,
    client: Any | None = None,
    backend: LlmBackend = "auto",
    cli_runner: Any | None = None,
) -> LlmReviewResult:
    """Produce a narrative defensive review by calling Claude.

    Resolves which backend to use (API SDK or `claude` CLI) based on available
    auth, then runs the existing prompt pack through it. Streams the SDK path
    so we never hit HTTP timeouts on long reviews. The CLI path runs synchronously
    via `claude -p --output-format=json`.
    """
    resolved_model = model or os.environ.get("ATTACKMAP_LLM_MODEL") or DEFAULT_MODEL
    resolved_effort = effort or DEFAULT_EFFORT

    rendered = render_review_prompts(scan, attack_surfaces, findings, attack_paths)
    if backend == "cli" and cli_runner is not None:
        chosen_backend: Literal["api", "cli"] = "cli"
    else:
        chosen_backend = _resolve_backend(backend, api_key=api_key, client=client)

    if chosen_backend == "api":
        return _run_via_sdk(
            rendered.system,
            rendered.user,
            model=resolved_model,
            effort=resolved_effort,
            max_tokens=max_tokens,
            api_key=api_key,
            client=client,
        )
    return _run_via_claude_cli(
        rendered.system,
        rendered.user,
        model=resolved_model,
        runner=cli_runner,
    )


__all__ = [
    "generate_llm_review",
    "LlmReviewError",
    "LlmReviewResult",
    "LlmBackend",
    "DEFAULT_MODEL",
    "DEFAULT_EFFORT",
    "DEFAULT_MAX_TOKENS",
]
