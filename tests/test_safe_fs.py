"""Repo-confined reads (#234) and symlink-safe report writes (#228)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import sdk
from attackmap.cli import app
from attackmap.models import Finding, ScanResult
from attackmap.review_prompts import _code_excerpts
from attackmap.safe_fs import (
    UnsafePathError,
    contained_file,
    ensure_output_dir,
    is_contained,
    safe_write_text,
    walk_repo,
)
from attackmap.scanner import scan_repo

runner = CliRunner()
OUTSIDE_SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture
def hostile(tmp_path: Path) -> Path:
    """repo/ with an in-repo file symlink, a dir symlink and a loop, all
    pointing out of (or around) the tree; outside/ holds a secret."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "creds.py").write_text(f'TOKEN = "{OUTSIDE_SECRET}"\n', encoding="utf-8")
    (outside / "pkg").mkdir()
    (outside / "pkg" / "leak.py").write_text(f'KEY = "{OUTSIDE_SECRET}"\n', encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n",
        encoding="utf-8",
    )
    (repo / "linked.py").symlink_to(outside / "creds.py")
    (repo / "vendorlink").symlink_to(outside / "pkg", target_is_directory=True)
    (repo / "loop").symlink_to(repo, target_is_directory=True)
    return repo


def test_walk_repo_skips_symlinks_and_reports_them(hostile: Path) -> None:
    skipped: list[str] = []
    files = {p.relative_to(hostile).as_posix() for p in walk_repo(hostile, on_symlink=lambda p: skipped.append(p.name))}
    assert files == {"app.py"}
    assert sorted(skipped) == ["linked.py", "loop", "vendorlink"]


def test_scan_repo_never_reads_outside_root(hostile: Path) -> None:
    scan = scan_repo(hostile)
    dumped = scan.model_dump_json()
    assert OUTSIDE_SECRET[:12] not in dumped
    assert scan.files_scanned == 1
    assert sorted(scan.limitations) == [
        "symlink not followed: linked.py",
        "symlink not followed: loop",
        "symlink not followed: vendorlink",
    ]


def test_cli_reports_contain_no_outside_content(hostile: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(hostile), "-o", str(out)])
    assert result.exit_code == 0, result.output
    for artifact in out.iterdir():
        assert OUTSIDE_SECRET[:12] not in artifact.read_text(encoding="utf-8"), artifact.name
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert "symlink not followed: linked.py" in report["scan"]["limitations"]


def test_follow_mode_follows_only_in_repo_links(hostile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (hostile / "src").mkdir()
    (hostile / "src" / "real.py").write_text("x = 1\n", encoding="utf-8")
    (hostile / "alias.py").symlink_to(hostile / "src" / "real.py")
    monkeypatch.setenv("ATTACKMAP_FOLLOW_SYMLINKS", "1")
    files = {p.relative_to(hostile).as_posix() for p in walk_repo(hostile)}
    assert "alias.py" in files and "src/real.py" in files
    assert "linked.py" not in files and not any(f.startswith("vendorlink/") for f in files)
    assert not any(f.startswith("loop/") for f in files)


@pytest.mark.parametrize("rel", ["/etc/hosts", "../outside/creds.py", "~/.ssh/id_rsa", "linked.py", "loop/app.py"])
def test_contained_file_rejects_escapes(hostile: Path, rel: str) -> None:
    assert contained_file(hostile, rel) is None


def test_contained_file_accepts_repo_file(hostile: Path) -> None:
    assert contained_file(hostile, "app.py") == hostile / "app.py"
    assert is_contained(hostile, hostile / "app.py")


def test_code_excerpts_ignore_evidence_paths_outside_repo(hostile: Path, tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("SECRET_OUTSIDE = 1\n", encoding="utf-8")
    scan = ScanResult(root=str(hostile))
    findings = [
        Finding(title="a", severity="high", mitigation="m", evidence=["/etc/hosts:1 — x"]),
        Finding(title="b", severity="high", mitigation="m", evidence=["../x.py:1 — x"]),
        Finding(title="c", severity="high", mitigation="m", evidence=["linked.py:1 — x"]),
        Finding(title="d", severity="high", mitigation="m", evidence=["app.py:4 — route"]),
    ]
    excerpts = _code_excerpts(scan, findings)
    assert list(excerpts) == ["app.py:4"]
    assert "SECRET_OUTSIDE" not in json.dumps(excerpts)


def test_sdk_exports_confined_helpers() -> None:
    for name in ("walk_repo", "is_contained", "contained_file", "read_repo_text"):
        assert name in sdk.__all__ and callable(getattr(sdk, name))


# ---------- write side (#228) ----------


def test_safe_write_refuses_planted_symlink(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL\n", encoding="utf-8")
    (out / "attackmap-report.json").symlink_to(victim)
    with pytest.raises(UnsafePathError):
        safe_write_text(out, out / "attackmap-report.json", "pwned")
    assert victim.read_text(encoding="utf-8") == "ORIGINAL\n"


def test_safe_write_refuses_outside_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    with pytest.raises(UnsafePathError):
        safe_write_text(out, tmp_path / "elsewhere.txt", "x")


def test_ensure_output_dir_refuses_symlinked_dir_in_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    (checkout / "reports").symlink_to(target, target_is_directory=True)
    monkeypatch.chdir(checkout)
    with pytest.raises(UnsafePathError):
        ensure_output_dir("reports")
    with pytest.raises(UnsafePathError):
        ensure_output_dir("reports/sub")


def test_cli_pr_comment_symlink_repro_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The issue's repro: a committed symlink at the PR-comment path."""
    repo = tmp_path / "repoQ"
    (repo / "attackmap-reports").mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL\n", encoding="utf-8")
    (repo / "attackmap-reports" / "pr-comment.md").symlink_to(victim)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        ["analyze", ".", "--output", "attackmap-reports", "--pr-comment", "attackmap-reports/pr-comment.md"],
    )
    assert result.exit_code == 2
    assert "symlink" in result.output
    assert victim.read_text(encoding="utf-8") == "ORIGINAL\n"


def test_cli_report_symlink_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    (repo / "reports").mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    victim = tmp_path / ".bashrc"
    victim.write_text("ORIGINAL\n", encoding="utf-8")
    (repo / "reports" / "attackmap-report.json").symlink_to(victim)
    monkeypatch.chdir(repo)
    result = runner.invoke(app, ["analyze", "."])
    assert result.exit_code == 2
    assert victim.read_text(encoding="utf-8") == "ORIGINAL\n"


def test_limitations_are_unioned_across_analyzer_results() -> None:
    from attackmap.analyzers import merge_analyzer_results

    a = ScanResult(root=".", limitations=["symlink not followed: a.py"])
    b = ScanResult(root=".", limitations=["symlink not followed: a.py", "symlink not followed: b.py"])
    merged = merge_analyzer_results([a, b], root=".")
    assert merged.limitations == ["symlink not followed: a.py", "symlink not followed: b.py"]


def test_ensure_output_dir_allows_system_symlinks_when_cwd_is_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # macOS: /var and /tmp are symlinks to /private/...; a GUI-launched or
    # XCTest-spawned CLI runs with cwd "/" and must still write to the temp dir.
    sys_dir = tmp_path / "private" / "var"
    sys_dir.mkdir(parents=True)
    (tmp_path / "var").symlink_to(sys_dir)
    monkeypatch.chdir(tmp_path)
    out = ensure_output_dir("var/folders/out")
    assert (sys_dir / "folders" / "out").is_dir()
    assert out == Path("var/folders/out")


def test_ensure_output_dir_still_refuses_link_leaving_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkout = tmp_path / "repo"
    elsewhere = tmp_path / "elsewhere"
    checkout.mkdir()
    elsewhere.mkdir()
    (checkout / "reports").symlink_to(elsewhere)
    monkeypatch.chdir(checkout)
    with pytest.raises(UnsafePathError):
        ensure_output_dir("reports/sub")
