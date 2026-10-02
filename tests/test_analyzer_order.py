"""Analyzer run order follows metadata.priority; opt-in analyzers need -m (#221)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import analyzers as analyzers_mod
from attackmap.analyzers import (
    BuiltinPythonWebAnalyzer,
    analyze_repository,
    get_builtin_repository_analyzers,
    resolve_run_analyzers,
)
from attackmap.cli import app
from attackmap.sdk.models import Route, ScanResult

APP = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/hash', methods=['POST'])\ndef h():\n    return 'ok'\n"


class _Plugin:
    def __init__(self, name: str, *, priority: int, enabled_by_default: bool) -> None:
        self.name = name
        self.metadata = BuiltinPythonWebAnalyzer.metadata.model_copy(
            update={"name": name, "display_name": name, "priority": priority, "enabled_by_default": enabled_by_default}
        )

    def analyze(self, root: Path) -> ScanResult:
        return ScanResult(
            root=str(root),
            routes=[Route(path="/hash", method="POST", file="app.py", line=4)],
        )


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    return tmp_path


def _registry(monkeypatch: pytest.MonkeyPatch, *plugins: _Plugin) -> None:
    monkeypatch.setattr(
        analyzers_mod, "get_registered_analyzers", lambda: [*get_builtin_repository_analyzers(), *plugins]
    )


def test_run_order_is_priority_then_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _registry(monkeypatch, _Plugin("zz-early", priority=0, enabled_by_default=True))
    names = [a.name for a in resolve_run_analyzers(_repo(tmp_path))]
    assert names[0] == "zz-early"
    assert names.index("python-web") < names.index("default")
    explicit = [get_builtin_repository_analyzers()[-1], _Plugin("b", priority=20, enabled_by_default=True), BuiltinPythonWebAnalyzer()]
    assert [a.name for a in resolve_run_analyzers(tmp_path, analyzers=explicit)] == ["b", "python-web", "default"]


def test_low_priority_plugin_wins_duplicate_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _registry(monkeypatch, _Plugin("flask-deep", priority=0, enabled_by_default=True))
    scan = analyze_repository(_repo(tmp_path))
    route = next(r for r in scan.routes if r.path == "/hash")
    assert route.source_analyzer == "flask-deep"


def test_opt_in_plugin_skipped_without_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _registry(monkeypatch, _Plugin("flask-deep", priority=0, enabled_by_default=False))
    matches: list[str] = []
    names = [a.name for a in resolve_run_analyzers(_repo(tmp_path), opt_in_matches=matches)]
    assert "flask-deep" not in names
    assert matches == ["flask-deep"]
    scan = analyze_repository(tmp_path)
    assert {r.source_analyzer for r in scan.routes} == {"python-web"}


def test_opt_in_plugin_runs_when_selected(tmp_path: Path) -> None:
    plugin = _Plugin("flask-deep", priority=0, enabled_by_default=False)
    scan = analyze_repository(_repo(tmp_path), analyzers=[BuiltinPythonWebAnalyzer(), plugin])
    assert next(r for r in scan.routes if r.path == "/hash").source_analyzer == "flask-deep"


def test_cli_hint_and_modules_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _registry(monkeypatch, _Plugin("flask-deep", priority=0, enabled_by_default=False))
    runner = CliRunner()
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-o", str(tmp_path / "out"), "--format", "json"])
    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert "Opt-in analyzers match this repo but were not run: flask-deep. Enable with -m flask-deep." in flat

    listed = json.loads(runner.invoke(app, ["modules", "--json"]).output)
    assert listed[0]["name"] == "flask-deep"
    assert listed[0]["priority"] == 0 and listed[0]["enabled_by_default"] is False
    assert [m["priority"] for m in listed] == sorted(m["priority"] for m in listed)
