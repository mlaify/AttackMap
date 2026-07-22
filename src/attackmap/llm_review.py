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
from .review_prompts import (
    render_critic_prompts,
    render_hunt_generate_prompts,
    render_hunt_prompts,
    render_hunt_verify_prompts,
    render_remediation_prompts,
    render_review_prompts,
    render_skeptic_prompts,
    render_triage_prompts,
)

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "high"
DEFAULT_MAX_TOKENS = 32000

# Fast mode (2.5x output speed, premium price) is a research-preview beta and
# only runs on the Opus 4.8 / 4.7 tiers via the API backend — the `claude` CLI
# backend and other models silently fall back to standard speed.
FAST_MODE_BETA = "fast-mode-2026-02-01"
FAST_CAPABLE_MODELS = frozenset({"claude-opus-4-8", "claude-opus-4-7"})
CLAUDE_CLI_TIMEOUT_SECONDS = 600

# OpenAI / Codex provider. `gpt-5-codex` is the code-optimized GPT-5 (Responses
# API only) and the safe default; any other model ID is passed through verbatim
# so we never have to chase OpenAI's point-release churn. Reasoning effort maps
# onto the Responses API's `reasoning.effort` — OpenAI exposes low/medium/high,
# so our extended tiers (xhigh/max) clamp down to "high".
OPENAI_DEFAULT_MODEL = "gpt-5-codex"
OPENAI_API_TIMEOUT_SECONDS = 900
CODEX_CLI_TIMEOUT_SECONDS = 900
OPENAI_EFFORT_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
}

LlmProvider = Literal["claude", "openai"]
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
    speed: str = "standard",
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

    # Fast mode needs the beta endpoint + flag + top-level speed, and only on
    # the Opus 4.8/4.7 tiers. Anything else runs at standard speed.
    fast = speed == "fast" and model in FAST_CAPABLE_MODELS
    messages_api = sdk_client.messages
    if fast:
        request_kwargs["speed"] = "fast"
        request_kwargs["betas"] = [FAST_MODE_BETA]
        messages_api = sdk_client.beta.messages

    try:
        with messages_api.stream(**request_kwargs) as stream:
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


def _anthropic_sdk_available() -> bool:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


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
        # The CLI returns an unhelpful mix here:
        #  - `subtype` is often the literal "success" even when is_error=true
        #  - `result` carries the human-readable message ("Not logged in · Please run /login")
        #  - `errors` is sometimes absent
        # Prefer `result` when it looks like a message; fall back to `errors`,
        # then to `subtype`. Never show "success" — it just confuses users.
        detail: str | None = None
        result_text = payload.get("result")
        if isinstance(result_text, str) and result_text.strip():
            detail = result_text.strip()
        elif payload.get("errors"):
            detail = "; ".join(str(e) for e in payload["errors"])
        else:
            subtype = payload.get("subtype")
            if isinstance(subtype, str) and subtype and subtype != "success":
                detail = subtype
        detail = detail or "unknown error"
        hint = ""
        low = detail.lower()
        if "not logged in" in low or "/login" in low:
            hint = (
                " Run `claude login` (or `claude /login` inside the CLI), "
                "or use --llm-backend api with ANTHROPIC_API_KEY set."
            )
        raise LlmReviewError(f"`claude` CLI reported an error: {detail}.{hint}")

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


# ---------- OpenAI SDK backend (Responses API) ----------


def _resolve_openai_client(api_key: str | None, client: Any | None) -> Any:
    if client is not None:
        return client
    try:
        import openai
    except ImportError as exc:
        raise LlmReviewError(
            "The openai SDK is not installed. Install with `pip install attackmap[llm]` "
            "to use the OpenAI API backend, or install the `codex` CLI for the CLI backend."
        ) from exc

    resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not resolved_key:
        raise LlmReviewError(
            "No OpenAI API credentials found. Set OPENAI_API_KEY, or install the `codex` "
            "CLI and run `codex login` to use --llm-backend cli."
        )
    return openai.OpenAI(api_key=resolved_key, timeout=OPENAI_API_TIMEOUT_SECONDS)


def _openai_output_text(response: Any) -> str:
    text = getattr(response, "output_text", None)
    if isinstance(text, str) and text.strip():
        return text.strip()
    # Fallback: walk output items → content blocks → text, for SDK/response
    # shapes where the `output_text` convenience isn't populated.
    parts: list[str] = []
    for item in getattr(response, "output", None) or []:
        for block in getattr(item, "content", None) or []:
            value = getattr(block, "text", None)
            if isinstance(value, str) and value:
                parts.append(value)
    return "\n".join(parts).strip()


def _openai_usage(usage: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for field in ("input_tokens", "output_tokens"):
        value = getattr(usage, field, None)
        if isinstance(value, int):
            out[field] = value
    return out


def _run_via_openai_sdk(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    effort: str,
    max_tokens: int,
    api_key: str | None,
    client: Any | None,
) -> LlmReviewResult:
    oi = _resolve_openai_client(api_key, client)
    reasoning_effort = OPENAI_EFFORT_MAP.get(effort, "high")

    try:
        response = oi.responses.create(
            model=model,
            instructions=rendered_system,
            input=rendered_user,
            reasoning={"effort": reasoning_effort},
            max_output_tokens=max_tokens,
        )
    except LlmReviewError:
        raise
    except Exception as exc:  # pragma: no cover - surface SDK errors verbatim
        raise LlmReviewError(f"OpenAI API call failed: {exc}") from exc

    markdown = _openai_output_text(response)
    if not markdown:
        raise LlmReviewError("OpenAI returned no text content for the review.")

    status = getattr(response, "status", None)
    return LlmReviewResult(
        markdown=markdown,
        model=str(getattr(response, "model", None) or model),
        stop_reason=status if isinstance(status, str) else None,
        usage=_openai_usage(getattr(response, "usage", None)),
        backend="api",
    )


# ---------- Codex CLI backend ----------


def _codex_cli_available() -> bool:
    return shutil.which("codex") is not None


def _openai_sdk_available() -> bool:
    try:
        import openai  # noqa: F401
    except ImportError:
        return False
    return True


def _run_via_codex_cli(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    effort: str,
    runner: Any | None = None,
) -> LlmReviewResult:
    """Invoke `codex exec` non-interactively and return the final message.

    `codex exec` treats the positional prompt as the instruction and piped
    stdin as additional context, so we pass the rendered system prompt as the
    argument and stream the (large) evidence pack in on stdin. It prints only
    the final agent message to stdout. Runs read-only so it can never mutate the
    working tree, and `--skip-git-repo-check` lets it run outside a git repo.

    The `runner` argument is only used by tests to inject a fake subprocess
    runner; in production we go straight to subprocess.run.
    """
    if runner is None and not _codex_cli_available():
        raise LlmReviewError(
            "`codex` CLI was not found on PATH. Install it (npm install -g @openai/codex) "
            "and run `codex login`, or set OPENAI_API_KEY to use --llm-backend api."
        )

    reasoning_effort = OPENAI_EFFORT_MAP.get(effort, "high")
    cmd = [
        "codex",
        "exec",
        "--model",
        model,
        "-c",
        f'model_reasoning_effort="{reasoning_effort}"',
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
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
                timeout=CODEX_CLI_TIMEOUT_SECONDS,
            )
        else:
            completed = runner(cmd, rendered_user)
    except FileNotFoundError as exc:
        raise LlmReviewError("`codex` CLI was not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LlmReviewError(
            f"`codex` CLI did not respond within {CODEX_CLI_TIMEOUT_SECONDS}s."
        ) from exc

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        hint = ""
        low = stderr.lower()
        if "not logged in" in low or "login" in low or "auth" in low:
            hint = (
                " Run `codex login`, or use --llm-backend api with OPENAI_API_KEY set."
            )
        raise LlmReviewError(
            f"`codex` CLI exited with status {completed.returncode}: "
            f"{stderr or '<no stderr>'}.{hint}"
        )
    if not stdout:
        raise LlmReviewError("`codex` CLI produced no output.")

    return LlmReviewResult(
        markdown=stdout,
        model=model,
        stop_reason=None,
        usage={},
        backend="cli",
    )


# ---------- Public entry point ----------


def _resolve_openai_backend(
    backend: LlmBackend,
    *,
    api_key: str | None,
    client: Any | None,
    codex_runner: Any | None,
) -> Literal["api", "cli"]:
    if backend == "api":
        return "api"
    if backend == "cli":
        if codex_runner is None and not _codex_cli_available():
            raise LlmReviewError(
                "`--llm-backend cli` was requested but the `codex` CLI is not on PATH."
            )
        return "cli"
    # auto
    if client is not None:
        return "api"
    has_key = bool(api_key or os.environ.get("OPENAI_API_KEY"))
    # Prefer the API backend only when the openai SDK is importable; otherwise
    # fall back to the `codex` CLI (needs no SDK) so a key set against an
    # SDK-less install still works via subscription auth.
    if has_key and _openai_sdk_available():
        return "api"
    if _codex_cli_available():
        return "cli"
    if has_key:
        return "api"  # no SDK and no CLI — surface the actionable SDK-missing error
    raise LlmReviewError(
        "No OpenAI backend available. Set OPENAI_API_KEY, or install the `codex` "
        "CLI and run `codex login`."
    )


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
    if client is not None:
        return "api"
    has_key = bool(
        api_key
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    )
    # Prefer the API backend only when the SDK is actually importable. Otherwise
    # fall back to the `claude` CLI (needs no SDK), so a key set against an
    # SDK-less install (e.g. Homebrew, which doesn't vendor `attackmap[llm]`)
    # still works via subscription auth instead of erroring.
    if has_key and _anthropic_sdk_available():
        return "api"
    if _claude_cli_available():
        return "cli"
    if has_key:
        return "api"  # no SDK and no CLI — surface the actionable SDK-missing error
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
    mode: Literal[
        "review", "hunt", "hunt_verify", "hunt_generate", "hunt_skeptic",
        "hunt_critic", "remediate", "triage",
    ] = "review",
    speed: Literal["standard", "fast"] = "standard",
    provider: LlmProvider = "claude",
    openai_client: Any | None = None,
    codex_runner: Any | None = None,
    hypotheses: list[dict] | None = None,
    lens: str | None = None,
    avoid_titles: list[str] | None = None,
    critic_hint: str | None = None,
) -> LlmReviewResult:
    """Produce a narrative defensive review — or, with ``mode="hunt"``, ranked
    vulnerability hypotheses (#80) — by calling an LLM.

    ``provider`` selects Claude (default) or OpenAI/Codex. For each provider,
    the backend resolves to an API SDK or a subscription CLI based on available
    auth, then runs the appropriate prompt pack through it. The Claude SDK path
    streams so we never hit HTTP timeouts on long reviews; the `claude` CLI path
    runs `claude -p --output-format=json`. The OpenAI path uses the Responses
    API; the `codex` CLI path runs `codex exec`. All modes share the same
    evidence grounding contract (every claim cites evidence IDs). ``speed`` (Fast
    mode) is Claude/API-only and ignored for OpenAI.
    """
    resolved_effort = effort or DEFAULT_EFFORT

    if mode == "hunt_skeptic":
        # The skeptic pass needs the fixed hypothesis list (#147a).
        rendered = render_skeptic_prompts(
            scan, attack_surfaces, findings, attack_paths, hypotheses or []
        )
    elif mode == "hunt_generate":
        # Generation can be primed with a lens (#147b) and prior-round context (#147c).
        rendered = render_hunt_generate_prompts(
            scan, attack_surfaces, findings, attack_paths,
            lens=lens, avoid_titles=avoid_titles, critic_hint=critic_hint,
        )
    elif mode == "hunt_critic":
        # The completeness critic names untried angles from the leads so far (#147c).
        rendered = render_critic_prompts(
            scan, attack_surfaces, findings, attack_paths, hypotheses or []
        )
    else:
        render = {
            "hunt": render_hunt_prompts,
            "hunt_verify": render_hunt_verify_prompts,
            "remediate": render_remediation_prompts,
            "triage": render_triage_prompts,
        }.get(mode, render_review_prompts)
        rendered = render(scan, attack_surfaces, findings, attack_paths)

    if provider == "openai":
        resolved_model = (
            model or os.environ.get("ATTACKMAP_OPENAI_MODEL") or OPENAI_DEFAULT_MODEL
        )
        if backend == "cli" and codex_runner is not None:
            chosen: Literal["api", "cli"] = "cli"
        else:
            chosen = _resolve_openai_backend(
                backend, api_key=api_key, client=openai_client, codex_runner=codex_runner
            )
        if chosen == "api":
            return _run_via_openai_sdk(
                rendered.system,
                rendered.user,
                model=resolved_model,
                effort=resolved_effort,
                max_tokens=max_tokens,
                api_key=api_key,
                client=openai_client,
            )
        return _run_via_codex_cli(
            rendered.system,
            rendered.user,
            model=resolved_model,
            effort=resolved_effort,
            runner=codex_runner,
        )

    resolved_model = model or os.environ.get("ATTACKMAP_LLM_MODEL") or DEFAULT_MODEL
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
            speed=speed,
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
    "LlmProvider",
    "DEFAULT_MODEL",
    "OPENAI_DEFAULT_MODEL",
    "DEFAULT_EFFORT",
    "DEFAULT_MAX_TOKENS",
]
