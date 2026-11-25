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

Optional dependency: `pip install "attackmap[llm] @ git+https://github.com/mlaify/AttackMap.git"` installs the anthropic SDK.
The CLI backend only requires the `claude` binary on PATH (no SDK install).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal

from .llm_models import (
    CLAUDE_DEFAULT_MODEL,
    CLAUDE_FAST_GA,
    CLAUDE_FAST_PREVIEW,
    claude_efforts,
    codex_catalog_by_slug,
)
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

_LLM_INSTALL = 'pip install "attackmap[llm] @ git+https://github.com/mlaify/AttackMap.git"'

DEFAULT_MODEL = CLAUDE_DEFAULT_MODEL  # claude-opus-5-5
DEFAULT_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "high"
DEFAULT_MAX_TOKENS = 32000

# Fast mode (up to 2.5x output speed, premium price), API backend only. GA on
# Opus 5.5 and Fable / Mythos 5.2 (plain `speed="fast"`); a research preview on
# Opus 5 (beta endpoint + flag, needs access). Other models and the `claude` CLI
# backend run at standard speed.
FAST_MODE_BETA = "fast-mode-2026-02-01"
FAST_CAPABLE_MODELS = CLAUDE_FAST_GA | CLAUDE_FAST_PREVIEW
# Server-side refusal fallback: when a model's safeguards decline, the API
# reruns the request on a model chosen for the refusal category, in the same
# call. Offered on these models; the answer names the model that served it.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACK_MODELS = frozenset(
    {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
)
# Haiku 4.5 predates adaptive thinking and `effort`; those fields are left out for it.
NO_ADAPTIVE_THINKING_MODELS = frozenset({"claude-haiku-4-5"})
CLAUDE_CLI_TIMEOUT_SECONDS = 600

# OpenAI / Codex provider. `gpt-5-codex` is the code-optimized GPT-5 (Responses
# API only) and the safe default; any other model ID is passed through verbatim
# so we never have to chase OpenAI's point-release churn. Reasoning effort maps
# onto the Responses API's `reasoning.effort` — OpenAI exposes low/medium/high,
# so our extended tiers (xhigh/max) clamp down to "high".
OPENAI_DEFAULT_MODEL = "gpt-6.2-sol"  # used only when the Codex catalog isn't readable
OPENAI_API_TIMEOUT_SECONDS = 900
CODEX_CLI_TIMEOUT_SECONDS = 900
OPENAI_EFFORT_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
}

# Codex's cyber access programs (`codex exec --cyber-access-program`). Omitted,
# Codex uses the account's own default, e.g. the Daybreak toggle in ChatGPT.
CYBER_ACCESS_PROGRAMS = ("standard", "daybreak_blue", "daybreak_red")

LlmProvider = Literal["claude", "openai", "local"]
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
            "The anthropic SDK is not installed. Install with "
            f"`{_LLM_INSTALL}` "
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


def _accepts(method_owner: Any, param: str) -> bool:
    """True when ``method_owner.stream`` takes ``param`` (or can't be inspected, e.g. a test double)."""
    import inspect

    stream = getattr(method_owner, "stream", None)
    if stream is None:
        return False
    try:
        params = inspect.signature(stream).parameters
    except (TypeError, ValueError):
        return True
    return param in params or any(p.kind is p.VAR_KEYWORD for p in params.values())


def _claude_effort(model: str, effort: str) -> str:
    """``effort`` if the model takes it, else the nearest lower level it supports."""
    levels = claude_efforts(model)
    if not levels or effort in levels:
        return effort
    order = ("low", "medium", "high", "xhigh", "max")
    for candidate in reversed(order[: order.index(effort) + 1] if effort in order else order):
        if candidate in levels:
            return candidate
    return levels[-1]


def _refusal_message(model: str, details: Any) -> str:
    category = getattr(details, "category", None)
    explanation = getattr(details, "explanation", None)
    message = f"{model} declined the request (stop_reason=refusal"
    message += f", category={category})" if category else ")"
    if explanation:
        message += f": {explanation}"
    if category == "cyber":
        message += (
            " Security analysis can trip the cyber safeguards. Organizations verified through Anthropic's "
            "Cyber Verification Program get adjusted safeguards and Claude Mythos models; list the models "
            "your credentials can use with `attackmap llm-models`."
        )
    return message


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
    fallback: bool = True,
) -> LlmReviewResult:
    sdk_client, _ = _resolve_sdk_client(api_key, client)

    request_kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": [
            {"type": "text", "text": rendered_system, "cache_control": {"type": "ephemeral"}}
        ],
        "messages": [{"role": "user", "content": rendered_user}],
    }
    if model not in NO_ADAPTIVE_THINKING_MODELS:
        request_kwargs["thinking"] = {"type": "adaptive"}
        request_kwargs["output_config"] = {"effort": _claude_effort(model, effort)}

    # Refusal fallback and preview-tier fast mode go through the beta endpoint;
    # GA fast mode is a plain parameter. Each is used only when the installed SDK
    # accepts it, so an older `anthropic` keeps working at standard behavior.
    betas: list[str] = []
    beta_api = getattr(sdk_client, "beta", None)
    beta_messages = getattr(beta_api, "messages", None)
    if fallback and model in FALLBACK_MODELS and _accepts(beta_messages, "fallbacks"):
        request_kwargs["fallbacks"] = "default"
        betas.append(FALLBACK_BETA)
    if speed == "fast" and model in CLAUDE_FAST_PREVIEW and _accepts(beta_messages, "speed"):
        request_kwargs["speed"] = "fast"
        betas.append(FAST_MODE_BETA)
    if speed == "fast" and model in CLAUDE_FAST_GA:
        if _accepts(beta_messages if betas else sdk_client.messages, "speed"):
            request_kwargs["speed"] = "fast"
    messages_api = sdk_client.messages
    if betas:
        request_kwargs["betas"] = betas
        messages_api = beta_messages

    try:
        with messages_api.stream(**request_kwargs) as stream:
            final_message = stream.get_final_message()
    except LlmReviewError:
        raise
    except Exception as exc:  # pragma: no cover - surface SDK errors verbatim
        raise LlmReviewError(f"Claude API call failed: {exc}") from exc

    stop_reason = getattr(final_message, "stop_reason", None)
    if stop_reason == "refusal":
        raise LlmReviewError(_refusal_message(model, getattr(final_message, "stop_details", None)))

    markdown = _extract_text(getattr(final_message, "content", []) or [])
    if not markdown:
        raise LlmReviewError("Claude returned no text content for the review.")

    served = getattr(final_message, "model", None)
    return LlmReviewResult(
        markdown=markdown,
        model=served if isinstance(served, str) and served else model,
        stop_reason=stop_reason if isinstance(stop_reason, str) else None,
        usage=_usage_dict(getattr(final_message, "usage", None)),
        backend="api",
    )


# ---------- CLI backend isolation (#232) ----------
#
# The CLI backends hand an *agent* the evidence pack, which is derived from an
# untrusted repository and may carry prompt injection. They are spawned so that
# nothing from that repository can configure the agent and the agent has as
# little reach as its CLI allows:
#   * cwd is a fresh empty temp dir, never the scan root or the caller's cwd,
#     so project-scoped `.claude/settings.json` (hooks, permissions),
#     `.mcp.json`, `CLAUDE.md` and `AGENTS.md` are never discovered;
#   * claude: no built-in tools, user-level settings only, no MCP servers, no
#     session persistence;
#   * codex: read-only sandbox rooted at the temp dir, no execpolicy rules,
#     ephemeral session. Codex has no tool-less mode, so its model can still
#     run read-only commands as the user; `--llm-backend api` is the only fully
#     tool-less path for OpenAI (documented in the README);
#   * the environment is scrubbed of credentials unrelated to the provider.
# If the installed CLI lacks the hardening flags we refuse to run it rather
# than fall back to an unhardened invocation.

CLAUDE_CLI_HARDENING_ARGS = (
    "--tools",
    "",
    "--setting-sources",
    "user",
    "--strict-mcp-config",
    "--mcp-config",
    '{"mcpServers":{}}',
    "--no-session-persistence",
)
_CLAUDE_REQUIRED_FLAGS = ("--tools", "--setting-sources", "--strict-mcp-config", "--no-session-persistence")
_CODEX_REQUIRED_FLAGS = ("--cd", "--ephemeral", "--ignore-rules", "--sandbox")

# Environment variables whose names look like credentials are not forwarded to
# the agent, except the ones the selected provider needs to authenticate.
_SENSITIVE_ENV_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|ACCESS_KEY|SESSION_KEY|AUTH)",
    re.IGNORECASE,
)
_CLOUD_ENV_PREFIXES = ("AWS_", "AZURE_", "GOOGLE_", "GCP_", "GCLOUD_", "CLOUDSDK_", "ANTHROPIC_VERTEX_")
_PROVIDER_ENV_ALLOW = {
    "claude": frozenset(
        {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL"}
    ),
    "openai": frozenset({"OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_API_KEY"}),
}
# Claude Code on Bedrock / Vertex / Foundry authenticates with cloud
# credentials, so those are kept when the user has opted into a 3P provider.
_CLAUDE_3P_SWITCHES = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")


def scrub_cli_env(env: dict[str, str], provider: LlmProvider) -> dict[str, str]:
    """Return a copy of ``env`` without credentials the agent doesn't need."""
    allow = _PROVIDER_ENV_ALLOW[provider]
    keep_cloud = provider == "claude" and any(env.get(k) for k in _CLAUDE_3P_SWITCHES)
    scrubbed: dict[str, str] = {}
    for name, value in env.items():
        upper = name.upper()
        if upper in allow:
            scrubbed[name] = value
            continue
        if upper.startswith(_CLOUD_ENV_PREFIXES):
            if keep_cloud:
                scrubbed[name] = value
            continue
        if _SENSITIVE_ENV_RE.search(upper):
            continue
        scrubbed[name] = value
    return scrubbed


@contextmanager
def isolated_cli_workdir() -> Iterator[str]:
    """A throwaway empty working directory for an agent CLI subprocess."""
    with tempfile.TemporaryDirectory(prefix="attackmap-llm-") as tmp:
        yield tmp


@lru_cache(maxsize=None)
def _cli_help_text(argv: tuple[str, ...]) -> str:
    try:
        with isolated_cli_workdir() as cwd:
            completed = subprocess.run(
                list(argv), capture_output=True, text=True, check=False, timeout=30, cwd=cwd
            )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout or "") + (completed.stderr or "")


def _require_hardening_flags(name: str, help_argv: tuple[str, ...], flags: tuple[str, ...]) -> None:
    help_text = _cli_help_text(help_argv)
    missing = [flag for flag in flags if flag not in help_text]
    if missing:
        raise LlmReviewError(
            f"The installed `{name}` CLI does not support {', '.join(missing)}, which AttackMap "
            f"needs to run it isolated from the scanned repository. Upgrade `{name}`, or use "
            "`--llm-backend api`."
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
        *CLAUDE_CLI_HARDENING_ARGS,
        "--model",
        model,
        "--system-prompt",
        rendered_system,
    ]

    try:
        if runner is None:
            _require_hardening_flags("claude", ("claude", "--help"), _CLAUDE_REQUIRED_FLAGS)
            with isolated_cli_workdir() as cwd:
                completed = subprocess.run(
                    cmd,
                    input=rendered_user,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=CLAUDE_CLI_TIMEOUT_SECONDS,
                    cwd=cwd,
                    env=scrub_cli_env(dict(os.environ), "claude"),
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


# ---------- Local model backend (#203) ----------
# Any OpenAI-compatible Chat Completions server on this machine or network:
# Ollama, llama.cpp `llama-server`, vLLM, LM Studio. Standard library only, and
# the evidence pack stays local: a host that isn't loopback, private or
# link-local is refused unless ATTACKMAP_LOCAL_LLM_ALLOW_REMOTE=1.

LOCAL_DEFAULT_URL = "http://127.0.0.1:11434/v1"  # Ollama
LOCAL_TIMEOUT_SECONDS = 900  # local models are slow on long evidence packs


def _local_host_ok(url: str) -> bool:
    import ipaddress
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _run_via_local(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str | None,
    max_tokens: int,
    base_url: str | None = None,
    opener: Any | None = None,
) -> LlmReviewResult:
    import urllib.request

    url = (base_url or os.environ.get("ATTACKMAP_LOCAL_LLM_URL") or LOCAL_DEFAULT_URL).rstrip("/")
    resolved_model = model or os.environ.get("ATTACKMAP_LOCAL_LLM_MODEL")
    if not resolved_model:
        raise LlmReviewError(
            "--llm-provider local needs a model: pass --llm-model (e.g. qwen2.5-coder:32b) "
            "or set ATTACKMAP_LOCAL_LLM_MODEL."
        )
    if not url.startswith(("http://", "https://")):
        raise LlmReviewError(f"Local model URL must be http(s): {url}")
    if not _local_host_ok(url) and os.environ.get("ATTACKMAP_LOCAL_LLM_ALLOW_REMOTE") != "1":
        raise LlmReviewError(
            f"{url} isn't on this machine or a private network, so the evidence pack would leave it. "
            "Point --llm-base-url at a local server, or set ATTACKMAP_LOCAL_LLM_ALLOW_REMOTE=1 to allow it."
        )
    body = json.dumps({
        "model": resolved_model,
        "messages": [{"role": "system", "content": rendered_system}, {"role": "user", "content": rendered_user}],
        "max_tokens": max_tokens,
        "stream": False,
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{url}/chat/completions", data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with (opener or urllib.request.urlopen)(request, timeout=LOCAL_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise LlmReviewError(f"Local model call to {url} failed: {exc}") from exc
    try:
        choice = payload["choices"][0]
        markdown = (choice["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise LlmReviewError(f"Local model at {url} returned no chat completion: {str(payload)[:200]}") from exc
    usage = payload.get("usage") or {}
    return LlmReviewResult(
        markdown=markdown,
        model=str(payload.get("model") or resolved_model),
        stop_reason=choice.get("finish_reason"),
        usage={
            k: v for k, v in (("input_tokens", usage.get("prompt_tokens")), ("output_tokens", usage.get("completion_tokens")))
            if isinstance(v, int)
        },
        backend="api",
    )


# ---------- OpenAI SDK backend (Responses API) ----------


def _resolve_openai_client(api_key: str | None, client: Any | None) -> Any:
    if client is not None:
        return client
    try:
        import openai
    except ImportError as exc:
        raise LlmReviewError(
            "The openai SDK is not installed. Install with "
            f"`{_LLM_INSTALL}` "
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


def _openai_effort(model: str, effort: str) -> str:
    """The Codex catalog's reasoning levels for ``model`` when known; else clamp to low/medium/high."""
    info = codex_catalog_by_slug().get(model)
    if info and info.efforts:
        if effort in info.efforts:
            return effort
        order = ("low", "medium", "high", "xhigh", "max")
        for candidate in reversed(order[: order.index(effort) + 1] if effort in order else order):
            if candidate in info.efforts:
                return candidate
    return OPENAI_EFFORT_MAP.get(effort, "high")


def _openai_default_model() -> str:
    """The account's Codex default (first listed model in its catalog), else the static default."""
    listed = [m for m in codex_catalog_by_slug().values() if m.default]
    return listed[0].id if listed else OPENAI_DEFAULT_MODEL


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
    reasoning_effort = _openai_effort(model, effort)

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
    access_program: str | None = None,
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

    reasoning_effort = _openai_effort(model, effort)
    access_args = ["--cyber-access-program", access_program] if access_program else []

    def build_cmd(cwd: str) -> list[str]:
        return [
            "codex",
            "exec",
            "--model",
            model,
            "-c",
            f'model_reasoning_effort="{reasoning_effort}"',
            "--sandbox",
            "read-only",
            "--cd",
            cwd,
            "--ephemeral",
            "--ignore-rules",
            "--skip-git-repo-check",
            *access_args,
            rendered_system,
        ]

    try:
        with isolated_cli_workdir() as cwd:
            cmd = build_cmd(cwd)
            if runner is None:
                _require_hardening_flags("codex", ("codex", "exec", "--help"), _CODEX_REQUIRED_FLAGS)
                completed = subprocess.run(
                    cmd,
                    input=rendered_user,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=CODEX_CLI_TIMEOUT_SECONDS,
                    cwd=cwd,
                    env=scrub_cli_env(dict(os.environ), "openai"),
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
    # SDK-less install (one without the `llm` extra)
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
    access_program: str | None = None,
    fallback: bool = True,
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

    if provider == "local":
        return _run_via_local(rendered.system, rendered.user, model=model, max_tokens=max_tokens)

    if provider == "openai":
        resolved_model = model or os.environ.get("ATTACKMAP_OPENAI_MODEL") or _openai_default_model()
        access_program = access_program or os.environ.get("ATTACKMAP_OPENAI_ACCESS_PROGRAM") or None
        if access_program:
            if access_program not in CYBER_ACCESS_PROGRAMS:
                raise LlmReviewError(
                    f"Unknown access program {access_program!r}: use one of {', '.join(CYBER_ACCESS_PROGRAMS)}."
                )
            offered = (codex_catalog_by_slug().get(resolved_model) or None)
            programs = offered.access_programs.get("cyber") if offered else None
            if programs is not None and access_program not in programs:
                raise LlmReviewError(
                    f"{resolved_model} doesn't offer the {access_program} access program on this account "
                    f"(offered: {', '.join(programs) or 'none'}). See `attackmap llm-models --llm-provider openai`."
                )
        if backend == "cli" and codex_runner is not None:
            chosen: Literal["api", "cli"] = "cli"
        else:
            chosen = _resolve_openai_backend(
                backend, api_key=api_key, client=openai_client, codex_runner=codex_runner
            )
        if chosen == "api" and access_program:
            raise LlmReviewError(
                "--llm-access-program needs the `codex` CLI backend (--llm-backend cli); "
                "the OpenAI API backend has no access-program option in AttackMap yet."
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
            access_program=access_program,
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
            fallback=fallback,
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
    "CYBER_ACCESS_PROGRAMS",
    "DEFAULT_MODEL",
    "OPENAI_DEFAULT_MODEL",
    "DEFAULT_EFFORT",
    "DEFAULT_MAX_TOKENS",
]
