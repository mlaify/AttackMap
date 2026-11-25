"""Extension points for installed packages: extra CLI commands and LLM hooks.

Analyzer plugins (`attackmap.analyzers`) add detection. These two groups let a
separately installed package extend the rest of AttackMap without forking it:

``attackmap.cli``
    Each entry point is a callable ``register(app: typer.Typer) -> None`` that
    adds commands to the ``attackmap`` CLI.

``attackmap.llm``
    Each entry point is an object (or a class, instantiated with no arguments)
    with any of these optional members:

    - ``llm_options: dict[str, dict]``: the ``--llm-option KEY=VALUE`` keys it
      understands, each ``{"description": str, "choices": [str, ...]}``
      (``choices`` optional). Unknown keys are rejected before a scan starts.
    - ``validate_llm_run(*, provider, backend, model, options) -> None``: raise
      ``ValueError`` to stop a run with a message (for example, an option the
      chosen model doesn't support).
    - ``codex_args(*, model, options) -> list[str]``: extra arguments for
      ``codex exec``.
    - ``refusal_hint(*, model, category) -> str | None``: a sentence appended
      to a Claude refusal message.

Extensions are never official plugins, so trusted-only mode
(``ATTACKMAP_TRUSTED_ANALYZERS_ONLY``, the GitHub Action's default) loads none
of them. ``attackmap capabilities`` lists the ones that loaded.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from importlib.metadata import entry_points
from typing import Any

from .analyzers import trusted_analyzers_only

logger = logging.getLogger(__name__)

CLI_GROUP = "attackmap.cli"
LLM_GROUP = "attackmap.llm"


def _entry_points(group: str) -> list[Any]:
    if trusted_analyzers_only():
        return []
    found = entry_points()
    candidates = found.select(group=group) if hasattr(found, "select") else found.get(group, ())
    return sorted(candidates, key=lambda ep: ep.name)


def _source(ep: Any) -> str:
    dist = getattr(ep, "dist", None)
    return f"{ep.name} ({getattr(dist, 'name', None) or 'unknown distribution'})"


_loaded_cli: list[str] = []


def _command_name(info: Any) -> str:
    callback = getattr(info, "callback", None)
    return getattr(info, "name", None) or getattr(callback, "__name__", "").replace("_", "-")


def load_cli_extensions(app: Any) -> list[str]:
    """Let installed packages add commands to ``app``; returns the ones that loaded.

    An extension can only add commands: one that reuses an existing command name
    is dropped, so a package can't replace `analyze` or another built-in.
    """
    registered = getattr(app, "registered_commands", None)
    for ep in _entry_points(CLI_GROUP):
        before = list(registered) if registered is not None else []
        taken = {_command_name(info) for info in before}
        try:
            ep.load()(app)
        except Exception as exc:  # one broken extension must not take the CLI down
            logger.warning("Skipping AttackMap CLI extension %s: %s", _source(ep), exc)
            if registered is not None:
                registered[:] = before
            continue
        if registered is not None:
            added = registered[len(before):]
            clashes = [info for info in added if _command_name(info) in taken]
            for info in clashes:
                logger.warning(
                    "AttackMap CLI extension %s tried to replace the '%s' command; ignored.",
                    _source(ep), _command_name(info),
                )
            registered[:] = before + [info for info in added if info not in clashes]
        _loaded_cli.append(_source(ep))
    return list(_loaded_cli)


@lru_cache(maxsize=1)
def llm_extensions() -> tuple[tuple[str, Any], ...]:
    loaded: list[tuple[str, Any]] = []
    for ep in _entry_points(LLM_GROUP):
        try:
            obj = ep.load()
            loaded.append((_source(ep), obj() if isinstance(obj, type) else obj))
        except Exception as exc:
            logger.warning("Skipping AttackMap LLM extension %s: %s", _source(ep), exc)
    return tuple(loaded)


def llm_options() -> dict[str, dict]:
    """Every ``--llm-option`` key the installed extensions understand."""
    options: dict[str, dict] = {}
    for _, ext in llm_extensions():
        for key, spec in (getattr(ext, "llm_options", None) or {}).items():
            options[str(key)] = dict(spec or {})
    return options


def validate_llm_run(*, provider: str, backend: str, model: str | None, options: dict[str, str]) -> None:
    for _, ext in llm_extensions():
        hook = getattr(ext, "validate_llm_run", None)
        if hook is not None:
            hook(provider=provider, backend=backend, model=model, options=options)


def codex_args(*, model: str | None, options: dict[str, str]) -> list[str]:
    args: list[str] = []
    for _, ext in llm_extensions():
        hook = getattr(ext, "codex_args", None)
        if hook is not None:
            args += [str(a) for a in hook(model=model, options=options) or ()]
    return args


def refusal_hints(*, model: str, category: str | None) -> list[str]:
    hints: list[str] = []
    for _, ext in llm_extensions():
        hook = getattr(ext, "refusal_hint", None)
        hint = hook(model=model, category=category) if hook is not None else None
        if hint:
            hints.append(str(hint))
    return hints


def loaded() -> dict[str, list[str]]:
    """What `attackmap capabilities` reports."""
    return {"cli": list(_loaded_cli), "llm": [name for name, _ in llm_extensions()]}


__all__ = [
    "CLI_GROUP",
    "LLM_GROUP",
    "codex_args",
    "llm_extensions",
    "llm_options",
    "load_cli_extensions",
    "loaded",
    "refusal_hints",
    "validate_llm_run",
]
