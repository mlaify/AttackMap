"""Read files and changed lines from a git ref (#238).

Used to trust only suppressions that already exist on a reference branch (the
PR's base): a pull request must not be able to suppress its own findings.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


class GitRefError(RuntimeError):
    """The ref can't be resolved, or the directory isn't a git checkout."""


# The scanned repository is untrusted, and so is its `.git/config`: it can set
# `core.fsmonitor`, `diff.external`, `core.pager` or textconv drivers that run
# arbitrary commands when git reads history. Every git call AttackMap makes
# overrides those, ignores system/global config, never prompts, and never
# lazily fetches missing objects from a promisor remote (#252).
_HARDENED_CONFIG = (
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=" + os.devnull,
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "core.attributesFile=" + os.devnull,
    "-c", "protocol.allow=never",
    "-c", "core.sshCommand=false",
)


def hardened_git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env


def hardened_git_command(root: Path, *args: str) -> list[str]:
    """``git -C root <hardening> --no-pager <args>`` (see ``_HARDENED_CONFIG``)."""
    return ["git", "-C", str(root), *_HARDENED_CONFIG, "--no-pager", *args]


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        hardened_git_command(root, *args),
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
        env=hardened_git_env(),
    )


def validate_ref(root: Path, ref: str) -> None:
    if not ref or ref.startswith("-"):
        raise GitRefError(f"invalid git ref {ref!r}")
    probe = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if probe.returncode != 0:
        raise GitRefError(
            f"git ref {ref!r} is not available in {root} (in CI, fetch the base branch first, "
            "e.g. git fetch --depth=1 origin <base>)"
        )


def show_file(root: Path, ref: str, rel: str) -> str | None:
    """Content of ``rel`` (relative to ``root``) at ``ref``; None if absent there."""
    result = _git(root, "show", f"{ref}:./{rel}")
    if result.returncode != 0:
        return None
    return result.stdout


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


def added_lines(root: Path, ref: str, rel: str) -> set[int]:
    """Line numbers of ``rel`` (working tree) that are new or changed since ``ref``."""
    result = _git(root, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-U0", ref, "--", rel)
    if result.returncode != 0:
        return set()
    lines: set[int] = set()
    for match in _HUNK.finditer(result.stdout):
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        lines.update(range(start, start + count))
    if not result.stdout and _git(root, "ls-files", "--error-unmatch", "--", rel).returncode != 0:
        # Untracked file: every line is new.
        try:
            return set(range(1, len((root / rel).read_text(encoding="utf-8", errors="replace").splitlines()) + 1))
        except OSError:
            return set()
    return lines
