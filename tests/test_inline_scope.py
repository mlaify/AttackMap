"""Inline directives are line-scoped; new suppressions don't look like fixes (#224)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

ROUTES = '''import hashlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/checksum", methods=["POST"])
def checksum():
    return hashlib.md5(request.data).hexdigest()  {directive}
'''
ADMIN = '''

@app.route("/admin/delete", methods=["POST"])
def delete_everything():
    return "gone"
'''


def _scan(repo: Path, out: Path, *extra: str):
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json", *extra])
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8")) if (out / "attackmap-report.json").exists() else {}
    return result, report


def _repo(tmp_path: Path, body: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text(body, encoding="utf-8")
    return repo


def _active_rules(report: dict) -> set[str]:
    return {f["rule_id"] for f in report["findings"]}


def test_line_directive_does_not_hide_other_findings_in_the_file(tmp_path: Path) -> None:
    """The issue's repro: a comment about a checksum must not hide a HIGH auth finding."""
    repo = _repo(tmp_path, ROUTES.format(directive="# attackmap:ignore legacy checksum only"))
    result, report = _scan(repo, tmp_path / "o")
    assert result.exit_code == 0, result.output
    assert "unauth-state-change" in _active_rules(report)
    assert "bare attackmap:ignore" in " ".join(_ANSI.sub("", result.output).split())


def test_later_instance_in_the_same_file_is_reported(tmp_path: Path) -> None:
    body = ROUTES.format(directive="").replace(
        '@app.route("/checksum", methods=["POST"])',
        '@app.route("/checksum", methods=["POST"])  # attackmap:ignore[unauth-state-change] public checksum API',
    ) + ADMIN.replace('"/admin/delete"', '"/reports/delete"')
    _, report = _scan(_repo(tmp_path, body), tmp_path / "o")
    finding = next(f for f in report["findings"] if f["rule_id"] == "unauth-state-change")
    lines = {loc["line"] for loc in finding["locations"]}
    assert 7 not in lines  # the annotated route's instance is dropped …
    assert lines and all(line > 9 for line in lines)  # … the later route in the same file still reports


def test_directive_on_the_line_above_covers_the_next_line(tmp_path: Path) -> None:
    body = ROUTES.format(directive="").replace(
        '@app.route("/checksum"', '# attackmap:ignore[unauth-state-change] public checksum API\n@app.route("/checksum"'
    )
    _, report = _scan(_repo(tmp_path, body), tmp_path / "o")
    assert "unauth-state-change" not in _active_rules(report)
    assert any(s["rule_id"] == "unauth-state-change" for s in report["suppressed_findings"])


def test_ignore_file_is_the_explicit_file_wide_form(tmp_path: Path) -> None:
    body = "# attackmap:ignore-file[unauth-state-change] internal-only service\n" + ROUTES.format(directive="") + ADMIN
    _, report = _scan(_repo(tmp_path, body), tmp_path / "o")
    assert "unauth-state-change" not in _active_rules(report)


def test_newly_suppressed_is_not_resolved_and_can_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path, ROUTES.format(directive=""))
    _, _ = _scan(repo, tmp_path / "base")
    baseline = tmp_path / "base" / "attackmap-report.json"
    (repo / "app.py").write_text(
        "# attackmap:ignore-file[unauth-state-change] trust me\n" + ROUTES.format(directive=""), encoding="utf-8"
    )
    pr = tmp_path / "pr" / "pr-comment.md"
    result, _ = _scan(repo, tmp_path / "pr", "--baseline", str(baseline), "--diff-output", str(tmp_path / "pr" / "diff.md"),
                      "--pr-comment", str(pr), "--fail-on-new-suppression")
    flat = " ".join(_ANSI.sub("", result.output).split())
    assert result.exit_code == 1, result.output
    assert "0 resolved, 1 newly suppressed" in flat
    assert "Newly suppressed" in pr.read_text(encoding="utf-8")
    md = (tmp_path / "pr" / "diff.md").read_text(encoding="utf-8")
    resolved_section = md.split("## Resolved findings")[1].split("##")[0]
    assert "_none_" in resolved_section
