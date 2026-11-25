"""Which LLM models the current credentials can use (`attackmap llm-models`).

AttackMap passes any model ID straight through to the provider, so a model the
account can use (a verified-only Claude Mythos model, an OpenAI model behind
an access program such as Daybreak) always works with `--llm-model`. This
module answers the other half: which models *this* user has, so the CLI and
the macOS app can offer them instead of a fixed list.

Sources, most specific first:

- Claude, API backend: the Models API (`client.models.list()`) lists exactly
  the models the organization can call. Mythos models only appear for
  organizations verified through a program such as the Cyber Verification
  Program.
- Claude, `claude` CLI backend (a Claude subscription): Claude Code has no
  non-interactive model list, so the built-in catalog is returned with
  ``source="catalog"``; `check_claude_model` confirms one model by asking it
  for a one-word reply (opt-in, it spends a request).
- OpenAI, `codex` CLI backend (a ChatGPT login): `codex debug models` is the
  account's model catalog, with each model's reasoning levels, speed tiers and
  access programs (for example ``{"cyber": ["standard", "daybreak_blue"]}``).
- OpenAI, API backend: the Models API (`client.models.list()`).
- Local: the server's OpenAI-compatible ``GET /models``.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Any, Literal

ModelSource = Literal["account", "catalog"]

# Claude models AttackMap knows how to call, newest first within each line.
# `gated` marks models only some organizations can use.
_VERIFIED_ONLY = "verified organizations only (e.g. the Cyber Verification Program)"
CLAUDE_CATALOG: tuple[tuple[str, str, str | None], ...] = (
    ("claude-mythos-5-2", "Claude Mythos 5.2", _VERIFIED_ONLY),
    ("claude-fable-5-2", "Claude Fable 5.2", None),
    ("claude-opus-5-5", "Claude Opus 5.5", None),
    ("claude-sonnet-5-5", "Claude Sonnet 5.5", None),
    ("claude-haiku-5-5", "Claude Haiku 5.5", None),
    ("claude-mythos-5-1", "Claude Mythos 5.1", _VERIFIED_ONLY),
    ("claude-fable-5-1", "Claude Fable 5.1", None),
    ("claude-fable-5", "Claude Fable 5", None),
    ("claude-opus-5", "Claude Opus 5", None),
    ("claude-sonnet-5", "Claude Sonnet 5", None),
    ("claude-opus-4-8", "Claude Opus 4.8", None),
    ("claude-opus-4-7", "Claude Opus 4.7", None),
    ("claude-opus-4-6", "Claude Opus 4.6", None),
    ("claude-sonnet-4-6", "Claude Sonnet 4.6", None),
    ("claude-haiku-4-5", "Claude Haiku 4.5", None),
)
CLAUDE_DEFAULT_MODEL = "claude-opus-5-5"

ALL_EFFORTS = ("low", "medium", "high", "xhigh", "max")
# Effort levels per Claude model where they differ from all five.
_CLAUDE_EFFORTS: dict[str, tuple[str, ...]] = {
    "claude-opus-4-6": ("low", "medium", "high", "max"),
    "claude-sonnet-4-6": ("low", "medium", "high", "max"),
    "claude-haiku-4-5": (),
}
# Fast mode: GA (plain `speed="fast"`) and research preview (beta endpoint + flag, needs access).
CLAUDE_FAST_GA = frozenset({"claude-opus-5-5", "claude-fable-5-2", "claude-mythos-5-2"})
CLAUDE_FAST_PREVIEW = frozenset({"claude-opus-5"})


@dataclass(frozen=True)
class ModelInfo:
    id: str
    display_name: str
    provider: Literal["claude", "openai", "local"]
    source: ModelSource
    default: bool = False
    gated: str | None = None
    efforts: tuple[str, ...] = ()
    fast: bool = False
    access_programs: dict[str, list[str]] = field(default_factory=dict)
    deprecated: bool = False
    description: str | None = None

    def to_json(self) -> dict[str, Any]:
        out = asdict(self)
        out["efforts"] = list(self.efforts)
        return out


class ModelListError(RuntimeError):
    """The provider's model list couldn't be read."""


# ---------- Claude ----------


def claude_efforts(model: str) -> tuple[str, ...]:
    return _CLAUDE_EFFORTS.get(model, ALL_EFFORTS)


def _claude_info(model_id: str, display: str, source: ModelSource, gated: str | None, **extra: Any) -> ModelInfo:
    return ModelInfo(
        id=model_id,
        display_name=display,
        provider="claude",
        source=source,
        default=model_id == CLAUDE_DEFAULT_MODEL,
        gated=gated,
        efforts=claude_efforts(model_id),
        fast=model_id in CLAUDE_FAST_GA or model_id in CLAUDE_FAST_PREVIEW,
        **extra,
    )


def claude_catalog() -> list[ModelInfo]:
    """The built-in Claude catalog: models AttackMap can call, access not confirmed."""
    return [_claude_info(mid, name, "catalog", gated) for mid, name, gated in CLAUDE_CATALOG]


def list_claude_models_api(client: Any) -> list[ModelInfo]:
    """The models this organization can call, from the Models API."""
    gated_by_id = {mid: gated for mid, _, gated in CLAUDE_CATALOG}
    out: list[ModelInfo] = []
    try:
        for m in client.models.list():
            mid = str(getattr(m, "id", "") or "")
            if not mid:
                continue
            gated = gated_by_id.get(mid) or (_VERIFIED_ONLY if mid.startswith("claude-mythos") else None)
            out.append(
                _claude_info(
                    mid,
                    str(getattr(m, "display_name", None) or mid),
                    "account",
                    gated,
                    deprecated=bool(getattr(m, "deprecated_at", None)),
                )
            )
    except Exception as exc:
        raise ModelListError(f"Claude Models API call failed: {exc}") from exc
    return out


def check_claude_model(model: str, *, runner: Any | None = None) -> tuple[bool, str]:
    """Ask `model` through the `claude` CLI for a one-word reply.

    Claude Code can't list a subscription's models without running a request,
    so this is how to confirm a catalog model (a Mythos model, say) is on the
    account. Returns (available, detail). Spends one small request.
    """
    from .llm_review import CLAUDE_CLI_HARDENING_ARGS, isolated_cli_workdir, scrub_cli_env

    cmd = ["claude", "-p", "--output-format=json", *CLAUDE_CLI_HARDENING_ARGS, "--model", model]
    prompt = "Reply with the single word OK."
    try:
        if runner is not None:
            completed = runner(cmd, prompt)
        else:
            with isolated_cli_workdir() as cwd:
                completed = subprocess.run(
                    cmd, input=prompt, text=True, capture_output=True, check=False, timeout=120,
                    cwd=cwd, env=scrub_cli_env(dict(os.environ), "claude"),
                )
    except FileNotFoundError:
        return False, "the `claude` CLI is not on PATH"
    except subprocess.TimeoutExpired:
        return False, "no reply within 120s"
    try:
        payload = json.loads((completed.stdout or "").strip() or "{}")
    except json.JSONDecodeError:
        payload = {}
    if completed.returncode == 0 and payload and not payload.get("is_error"):
        return True, "available"
    detail = str(payload.get("result") or completed.stderr or completed.stdout or "").strip()
    return False, detail[:300] or f"exit status {completed.returncode}"


# ---------- OpenAI / Codex ----------


def _codex_catalog_raw(runner: Any | None = None) -> dict[str, Any]:
    cmd = ["codex", "debug", "models"]
    try:
        if runner is not None:
            completed = runner(cmd)
        else:
            completed = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=60)
    except FileNotFoundError as exc:
        raise ModelListError("the `codex` CLI is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ModelListError("`codex debug models` did not finish within 60s") from exc
    if completed.returncode != 0:
        raise ModelListError(f"`codex debug models` failed: {(completed.stderr or '').strip()[:300]}")
    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ModelListError("`codex debug models` did not print JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        raise ModelListError("`codex debug models` printed an unexpected shape")
    return data


def list_codex_models(*, include_hidden: bool = False, runner: Any | None = None) -> list[ModelInfo]:
    """The ChatGPT account's Codex catalog, in Codex's own priority order."""
    entries = [m for m in _codex_catalog_raw(runner)["models"] if isinstance(m, dict) and m.get("slug")]
    entries.sort(key=lambda m: (m.get("priority") is None, m.get("priority") or 0))
    listed = [m for m in entries if m.get("visibility") == "list"]
    default_slug = listed[0]["slug"] if listed else (entries[0]["slug"] if entries else None)
    out: list[ModelInfo] = []
    for m in entries:
        if m.get("visibility") != "list" and not include_hidden:
            continue
        programs = m.get("available_access_programs") or {}
        out.append(
            ModelInfo(
                id=str(m["slug"]),
                display_name=str(m.get("display_name") or m["slug"]),
                provider="openai",
                source="account",
                default=m["slug"] == default_slug,
                efforts=tuple(
                    str(level["effort"]) for level in m.get("supported_reasoning_levels") or []
                    if isinstance(level, dict) and level.get("effort")
                ),
                fast="fast" in (m.get("additional_speed_tiers") or []),
                access_programs={str(k): [str(x) for x in v] for k, v in programs.items() if isinstance(v, list)},
                description=m.get("description"),
            )
        )
    return out


@lru_cache(maxsize=1)
def codex_catalog_by_slug() -> dict[str, ModelInfo]:
    """Codex catalog keyed by model, cached for the process; empty if `codex` isn't usable."""
    try:
        return {m.id: m for m in list_codex_models(include_hidden=True)}
    except ModelListError:
        return {}


def list_openai_models_api(client: Any) -> list[ModelInfo]:
    out: list[ModelInfo] = []
    try:
        for m in client.models.list():
            mid = str(getattr(m, "id", "") or "")
            if mid:
                out.append(ModelInfo(id=mid, display_name=mid, provider="openai", source="account"))
    except Exception as exc:
        raise ModelListError(f"OpenAI Models API call failed: {exc}") from exc
    return out


# ---------- Local (OpenAI-compatible) ----------


def list_local_models(base_url: str, *, opener: Any | None = None) -> list[ModelInfo]:
    import urllib.request

    url = base_url.rstrip("/") + "/models"
    try:
        with (opener or urllib.request.urlopen)(url, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ModelListError(f"{url} failed: {exc}") from exc
    rows = payload.get("data") if isinstance(payload, dict) else None
    return [
        ModelInfo(id=str(r["id"]), display_name=str(r["id"]), provider="local", source="account")
        for r in rows or [] if isinstance(r, dict) and r.get("id")
    ]


__all__ = [
    "CLAUDE_CATALOG",
    "CLAUDE_DEFAULT_MODEL",
    "CLAUDE_FAST_GA",
    "CLAUDE_FAST_PREVIEW",
    "ModelInfo",
    "ModelListError",
    "check_claude_model",
    "claude_catalog",
    "claude_efforts",
    "codex_catalog_by_slug",
    "list_claude_models_api",
    "list_codex_models",
    "list_local_models",
    "list_openai_models_api",
]
