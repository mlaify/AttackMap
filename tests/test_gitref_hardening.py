"""The scanned repo's git config can't run commands through gitref (#252 follow-up)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from attackmap.gitref import added_lines, show_file

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _hostile_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo, marker = tmp_path / "repo", tmp_path / "pwned"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text("a = 1\nb = 2\nc = 3\n")
    (repo / ".gitattributes").write_text("* filter=evil diff=evil\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    for key, cmd in {
        "filter.evil.clean": f"sh -c 'touch {marker}; cat'",
        "filter.evil.smudge": f"sh -c 'touch {marker}; cat'",
        "diff.evil.textconv": f"sh -c 'touch {marker}; cat'",
        "diff.evil.command": f"sh -c 'touch {marker}'",
        "core.fsmonitor": f"sh -c 'touch {marker}'",
    }.items():
        _git(repo, "config", key, cmd)
    return repo, marker


def test_added_lines_runs_no_repo_configured_commands(tmp_path: Path) -> None:
    repo, marker = _hostile_repo(tmp_path)
    (repo / "app.py").write_text("a = 1\nB = 22\nc = 3\nd = 4\n")
    assert added_lines(repo, "HEAD", "app.py") == {2, 4}
    assert show_file(repo, "HEAD", "app.py") == "a = 1\nb = 2\nc = 3\n"
    assert not marker.exists(), "a repo-configured filter/textconv/fsmonitor command ran"


def test_added_lines_for_file_new_since_ref(tmp_path: Path) -> None:
    repo, marker = _hostile_repo(tmp_path)
    (repo / "new.py").write_text("x = 1\ny = 2\n")
    assert added_lines(repo, "HEAD", "new.py") == {1, 2}
    assert not marker.exists()
