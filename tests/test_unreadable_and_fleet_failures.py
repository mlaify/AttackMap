"""Unreadable files and failing fleet repos don't abort the run (#217)."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import cli
from attackmap.cli import app
from attackmap.scanner import scan_repo

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
APP = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n"
needs_chmod = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="chmod 000 is not enforced on Windows or for root",
)


def _flat(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


@needs_chmod
def test_unreadable_file_is_skipped_and_reported(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    locked = tmp_path / "locked.py"
    locked.write_text("x = 1\n", encoding="utf-8")
    locked.chmod(0)
    try:
        scan = scan_repo(tmp_path)
        assert [r.path for r in scan.routes] == ["/ok"]
        assert any(l.startswith("unreadable file skipped") and l.endswith("locked.py") for l in scan.limitations)
        result = runner.invoke(app, ["analyze", str(tmp_path), "-o", str(tmp_path.parent / "o"), "--format", "json"])
        assert result.exit_code == 0, result.output
        assert "Not analyzed: 1 unreadable file skipped" in _flat(result.output)
    finally:
        locked.chmod(0o644)


def test_fleet_continues_past_a_failing_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good, bad = tmp_path / "good", tmp_path / "bad"
    for d in (good, bad):
        d.mkdir()
        (d / "app.py").write_text(APP, encoding="utf-8")
    real = cli.analyze_repository

    def flaky(root, **kwargs):
        if Path(root).name == "bad":
            raise RuntimeError("analyzer blew up")
        return real(root, **kwargs)

    monkeypatch.setattr(cli, "analyze_repository", flaky)
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(bad), str(good), "-o", str(out)])
    assert result.exit_code == 1, result.output
    flat = _flat(result.output)
    assert "bad failed and was skipped — RuntimeError: analyzer blew up" in flat
    summary = json.loads((out / "fleet-summary.json").read_text(encoding="utf-8"))
    assert [r["repo_id"] for r in summary["repos"]] == ["good"]
    assert summary["failed"][0]["repo_id"] == "bad"
    assert "analyzer blew up" in (out / "fleet-summary.md").read_text(encoding="utf-8")
    assert (out / "good" / "attackmap-report.json").exists()


def test_usage_errors_still_stop_the_fleet(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        (d / "app.py").write_text(APP, encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(a), str(b), "--suppress-file", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 2
