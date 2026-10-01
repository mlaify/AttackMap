"""Read files and changed lines from a git ref (#238).

Used to trust only suppressions that already exist on a reference branch (the
PR's base): a pull request must not be able to suppress its own findings.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


class GitRefError(RuntimeError):
    """The ref can't be resolved, or the directory isn't a git checkout."""


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
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
    result = _git(root, "diff", "--no-color", "-U0", ref, "--", rel)
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
