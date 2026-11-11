"""AttackMap never scans its own report output (#216)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.safe_fs import OUTPUT_MARKER

runner = CliRunner()
SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
APP = (
    "import requests\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/p", methods=["POST"])\ndef p():\n'
    '    return requests.get(request.args["u"]).text\n'
    f'TOKEN = "{SECRET}"\nDB = "postgresql://u:pw123456@db/x"\n'
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP, encoding="utf-8")
    return repo


def _summary(report: dict) -> list[tuple]:
    return sorted((f["rule_id"], len(f.get("locations", []))) for f in report["findings"]) + [
        ("files", report["scan"]["files_scanned"]),
        ("secrets", len(report["scan"]["secret_hints"])),
        ("databases", len(report["scan"]["databases"])),
    ]


@pytest.mark.parametrize("out_name", [None, "attackmap-reports", "custom/out"])
def test_second_run_is_identical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out_name: str | None) -> None:
    repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    args = ["analyze", "."] + (["-o", out_name] if out_name else [])
    out = repo / (out_name or "reports")
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    report1 = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert (out / OUTPUT_MARKER).is_file()
    second = runner.invoke(app, args)
    assert second.exit_code == 0, second.output
    report2 = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert _summary(report1) == _summary(report2)


def test_fleet_output_is_excluded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    a, b = tmp_path / "svcA", tmp_path / "svcB"
    for d in (a, b):
        d.mkdir()
        (d / "app.py").write_text(APP, encoding="utf-8")
    monkeypatch.chdir(a)  # fleet output lands inside the first repo
    args = ["analyze", str(a), str(b), "-o", "fleet-out", "--format", "json"]
    assert runner.invoke(app, args).exit_code == 0
    first = json.loads((a / "fleet-out" / "fleet-summary.json").read_text(encoding="utf-8"))
    assert runner.invoke(app, args).exit_code == 0
    second = json.loads((a / "fleet-out" / "fleet-summary.json").read_text(encoding="utf-8"))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_reports_from_older_versions_are_not_reingested(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    old = repo / "old-reports"  # written before the marker existed
    old.mkdir()
    (old / "attackmap-report.json").write_text(json.dumps({"x": f"postgresql://a:b@{SECRET}"}), encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "o"), "--format", "json"])
    report = json.loads((tmp_path / "o" / "attackmap-report.json").read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert all(not d["file"].startswith("old-reports") for d in report["scan"]["databases"])


def test_dot_output_does_not_hide_the_repo(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for _ in range(2):
        result = runner.invoke(app, ["analyze", str(repo), "-o", str(repo), "--format", "json"])
        assert result.exit_code == 0
    report = json.loads((repo / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["scan"]["files_scanned"] == 1


# ---------------------------------------------------------------------------
# A committed marker must not hide a directory from a gated scan
# (GHSA-j544-8x8g-c3mw).
# ---------------------------------------------------------------------------

import shutil
import subprocess

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
NEW_SECRET = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        check=True, capture_output=True,
    )


def _base_repo(tmp_path: Path) -> Path:
    """`src/app.py` with findings, committed and tagged `base`; a baseline
    report in tmp_path/base."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text(APP, encoding="utf-8")
    (repo / "cli.py").write_text("def main():\n    print('hi')\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "tag", "base")
    base = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "base"), "--format", "json"])
    assert base.exit_code == 0, base.output
    return repo


def _pr_with_marker(repo: Path) -> None:
    (repo / "src" / OUTPUT_MARKER).write_text("", encoding="utf-8")
    (repo / "src" / "new.py").write_text(f'TOKEN = "{NEW_SECRET}"\n', encoding="utf-8")


def _gate(repo: Path, tmp_path: Path, *extra: str):
    result = runner.invoke(app, [
        "analyze", str(repo), "-o", str(tmp_path / "pr"), "--format", "json",
        "--baseline", str(tmp_path / "base" / "attackmap-report.json"), "--fail-on-new-high",
        "--pr-comment", str(tmp_path / "pr" / "pr-comment.md"), *extra,
    ])
    report = json.loads((tmp_path / "pr" / "attackmap-report.json").read_text(encoding="utf-8"))
    return result, report


@needs_git
def test_marker_added_since_the_base_ref_does_not_exclude_its_directory(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path)
    _pr_with_marker(repo)
    result, report = _gate(repo, tmp_path, "--suppress-from-ref", "base")
    assert result.exit_code == 1, result.output
    secret = next(f for f in report["findings"] if f["rule_id"] == "hardcoded-secret")
    assert "src/new.py" in {loc["file"] for loc in secret["locations"]}
    assert f"output marker src/{OUTPUT_MARKER} was added since base" in result.output
    assert report["scan"]["limitations"] == []


@needs_git
def test_marker_present_at_the_base_ref_is_still_honoured(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "reports").mkdir(parents=True)
    (repo / "app.py").write_text(APP, encoding="utf-8")
    (repo / "reports" / OUTPUT_MARKER).write_text("", encoding="utf-8")
    (repo / "reports" / "old.py").write_text(f'TOKEN = "{NEW_SECRET}"\n', encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "tag", "base")
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "o"), "--format", "json",
                                 "--suppress-from-ref", "base"])
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "o" / "attackmap-report.json").read_text(encoding="utf-8"))
    assert "was added since base" not in result.output
    assert report["scan"]["limitations"] == ["directory skipped (output marker): reports"]
    assert {loc["file"] for f in report["findings"] for loc in f.get("locations", [])} <= {"app.py"}


@needs_git
def test_own_output_dir_inside_the_repo_is_trusted_under_suppress_from_ref(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path)
    out = repo / "reports"
    first = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json", "--suppress-from-ref", "base"])
    assert first.exit_code == 0, first.output
    second = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json", "--suppress-from-ref", "base"])
    assert second.exit_code == 0, second.output
    assert "was added since base" not in second.output
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["scan"]["limitations"] == ["directory skipped (output marker): reports"]
    assert {loc["file"] for f in report["findings"] for loc in f.get("locations", [])} <= {"src/app.py", "cli.py"}


@needs_git
def test_marker_without_a_trusted_ref_is_recorded_and_gated(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path)
    _pr_with_marker(repo)
    result, report = _gate(repo, tmp_path, "--fail-on-new-suppression")
    assert report["scan"]["limitations"] == ["directory skipped (output marker): src"]
    assert "newly excluded from the scan" in result.output
    assert "failing per --fail-on-new-suppression" in result.output
    assert result.exit_code == 1, result.output
    comment = (tmp_path / "pr" / "pr-comment.md").read_text(encoding="utf-8")
    assert "### Newly excluded from the scan" in comment
    diff_md = (tmp_path / "pr" / "attackmap-diff.md").read_text(encoding="utf-8")
    assert "## Newly excluded from the scan" in diff_md
    assert "**0 resolved**" in diff_md
