"""Suppression governance (#238): PRs can't suppress their own findings,
expiry, instance-level paths, no match-everything globs."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.suppress import Suppression, SuppressionSet, drop_expired, load_suppress_file

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _flat(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def _git(repo: Path, *args: str) -> None:
    # Throwaway test repos: never sign (the developer's signing key may need a touch).
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        check=True, capture_output=True,
    )


def _init(repo: Path, files: dict[str, str]) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    for rel, body in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(body, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "tag", "base")


def _run(repo: Path, out: Path, *extra: str):
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json", *extra])
    report = json.loads((out / "attackmap-report.json").read_text()) if (out / "attackmap-report.json").exists() else None
    return result, report


def _rules(report: dict) -> set[str]:
    return {f["rule_id"] for f in report["findings"]}


@needs_git
def test_pr_cannot_suppress_its_own_finding(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo, {"app.py": "x = 1\n"})
    # The "PR": adds a secret and a suppress file that hides it.
    (repo / "app.py").write_text(f'TOKEN = "{SECRET}"\n', encoding="utf-8")
    (repo / ".attackmap-suppress.yaml").write_text(
        "suppress:\n  - rule: hardcoded-secret\n    reason: trust me\n", encoding="utf-8"
    )
    pr = tmp_path / "o" / "pr-comment.md"
    result, report = _run(repo, tmp_path / "o", "--suppress-from-ref", "base", "--pr-comment", str(pr))
    assert result.exit_code == 0, result.output
    assert "hardcoded-secret" in _rules(report)
    assert "added since base — NOT applied" in _flat(result.output)
    comment = pr.read_text(encoding="utf-8")
    assert "### Suppressions" in comment and "not applied" in comment

    # Opt-in: applied, but still listed.
    result, report = _run(repo, tmp_path / "o2", "--suppress-from-ref", "base", "--allow-pr-suppressions")
    assert "hardcoded-secret" not in _rules(report)
    assert "applied anyway" in _flat(result.output)


@needs_git
def test_suppression_already_on_base_still_applies(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo, {
        "app.py": f'TOKEN = "{SECRET}"\n',
        ".attackmap-suppress.yaml": "suppress:\n  - rule: hardcoded-secret\n    reason: accepted\n",
    })
    result, report = _run(repo, tmp_path / "o", "--suppress-from-ref", "base")
    assert result.exit_code == 0, result.output
    assert "hardcoded-secret" not in _rules(report)


@needs_git
def test_inline_directive_added_by_the_pr_is_pending(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo, {"app.py": f'TOKEN = "{SECRET}"\n'})
    (repo / "app.py").write_text(
        f'TOKEN = "{SECRET}"  # attackmap:ignore[hardcoded-secret] fine\n', encoding="utf-8"
    )
    result, report = _run(repo, tmp_path / "o", "--suppress-from-ref", "base")
    assert "hardcoded-secret" in _rules(report)
    assert "NOT applied" in _flat(result.output)


@needs_git
def test_unknown_ref_is_a_clear_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo, {"app.py": "x = 1\n"})
    result, _ = _run(repo, tmp_path / "o", "--suppress-from-ref", "no-such-ref")
    assert result.exit_code != 0
    assert "is not available" in _flat(result.output)


def test_path_suppression_is_per_instance_not_per_aggregate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    for i in range(10):
        (repo / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
        (repo / "tests" / "fixtures" / f"f{i}.py").write_text(f'K = "{SECRET[:-2]}{i:02d}"\n', encoding="utf-8")
    (repo / "app").mkdir()
    (repo / "app" / "settings.py").write_text(f'K = "{SECRET}"\n', encoding="utf-8")
    (repo / ".attackmap-suppress.yaml").write_text(
        "suppress:\n  - rule: hardcoded-secret\n    reason: fixtures\n    paths: ['tests/fixtures/**']\n", encoding="utf-8"
    )
    _, report = _run(repo, tmp_path / "o")
    finding = next(f for f in report["findings"] if f["rule_id"] == "hardcoded-secret")
    assert {loc["file"] for loc in finding["locations"]} == {"app/settings.py"}


def test_expired_entries_warn_and_are_not_applied(tmp_path: Path) -> None:
    past = (date.today() - timedelta(days=1)).isoformat()
    (tmp_path / "app.py").write_text(f'TOKEN = "{SECRET}"\n', encoding="utf-8")
    (tmp_path / ".attackmap-suppress.yaml").write_text(
        f"suppress:\n  - rule: hardcoded-secret\n    reason: temp\n    expires: {past}\n    owner: alice\n",
        encoding="utf-8",
    )
    result, report = _run(tmp_path, tmp_path / "o")
    assert result.exit_code == 0
    assert "hardcoded-secret" in _rules(report)
    assert f"expired on {past} (owner: alice)" in _flat(result.output)
    strict, _ = _run(tmp_path, tmp_path / "o2", "--strict-suppressions")
    assert strict.exit_code == 2


def test_inline_until_date_expires(tmp_path: Path) -> None:
    sups = [Suppression(reason="x", rule="r", path="a.py", expires=date(2020, 1, 1))]
    warnings: list[str] = []
    live, expired = drop_expired(sups, warnings, today=date(2026, 1, 1))
    assert live == [] and len(expired) == 1 and warnings


@pytest.mark.parametrize("glob", ["*", "**", "**/*", "/", "./**"])
def test_match_everything_globs_are_rejected(tmp_path: Path, glob: str) -> None:
    (tmp_path / ".attackmap-suppress.yaml").write_text(
        f"suppress:\n  - path: '{glob}'\n    reason: silence everything\n", encoding="utf-8"
    )
    warnings: list[str] = []
    assert load_suppress_file(tmp_path, warnings) == []
    assert any("would suppress every file" in w for w in warnings)


def test_metadata_is_loaded(tmp_path: Path) -> None:
    (tmp_path / ".attackmap-suppress.yaml").write_text(
        "suppress:\n  - rule: hardcoded-secret\n    reason: r\n    expires: 2099-01-01\n"
        "    owner: sec-team\n    ticket: https://tracker.example/SEC-1\n",
        encoding="utf-8",
    )
    sup = load_suppress_file(tmp_path, [])[0]
    assert (sup.expires, sup.owner, sup.ticket) == (date(2099, 1, 1), "sec-team", "https://tracker.example/SEC-1")
    assert SuppressionSet([sup]).pending == []
