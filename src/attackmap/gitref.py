"""Read files and changed lines from a git ref (#238).

Used to trust only suppressions that already exist on a reference branch (the
PR's base): a pull request must not be able to suppress its own findings.
"""

from __future__ import annotations

import difflib
import os
import subprocess
from pathlib import Path

from .safe_fs import UnsafePathError, read_repo_text


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
    """Content of ``rel`` (relative to ``root``) at ``ref``; None if absent there.

    `cat-file blob` returns the raw object: no textconv and no filter drivers,
    which a hostile `.git/config` could point at arbitrary commands.
    """
    result = _git(root, "cat-file", "blob", f"{ref}:./{rel}")
    if result.returncode != 0:
        return None
    return result.stdout


def added_lines(root: Path, ref: str, rel: str) -> set[int]:
    """Line numbers of ``rel`` (working tree) that are new or changed since ``ref``.

    Computed in Python from the blob at ``ref`` and the working file, never by
    `git diff <ref> -- <file>`: diffing against the working tree runs the
    repo's `filter.<driver>.clean` commands, which `--no-textconv` and
    `--no-ext-diff` don't disable, so a scanned repo could execute code.
    """
    try:
        current = read_repo_text(root, rel, errors="replace").splitlines()
    except (OSError, UnsafePathError):
        return set()
    previous = show_file(root, ref, rel)
    if previous is None:
        return set(range(1, len(current) + 1))  # new since ref (or untracked)
    matcher = difflib.SequenceMatcher(None, previous.splitlines(), current, autojunk=False)
    lines: set[int] = set()
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            lines.update(range(j1 + 1, j2 + 1))
    return lines
