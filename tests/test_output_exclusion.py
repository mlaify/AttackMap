"""AttackMap never scans its own report output (#216)."""

from __future__ import annotations

import json
import os
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
