"""One failing analyzer doesn't abort the scan (#220)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import analyzers as analyzers_mod
from attackmap.analyzers import BuiltinPythonWebAnalyzer, analyze_repository
from attackmap.cli import app

APP = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class _Bad:
    def __init__(self, name: str, behavior: object) -> None:
        self.name = name
        self._behavior = behavior
        self.metadata = BuiltinPythonWebAnalyzer.metadata.model_copy(
            update={"name": name, "display_name": name}
        )

    def analyze(self, root: Path):
        if isinstance(self._behavior, BaseException):
            raise self._behavior
        return self._behavior


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP, encoding="utf-8")
    return repo


@pytest.mark.parametrize(
    "behavior, error_type",
    [
        (RuntimeError("plugin bug"), "RuntimeError"),
        (None, "AnalyzerResultError"),
        (["routes"], "AnalyzerResultError"),
        ({"routes": [{"path": 1}]}, "ValidationError"),
    ],
)
def test_failing_analyzer_is_skipped(tmp_path: Path, behavior: object, error_type: str) -> None:
    scan = analyze_repository(_repo(tmp_path), analyzers=[_Bad("broken", behavior), BuiltinPythonWebAnalyzer()])
    assert [r.path for r in scan.routes] == ["/ok"]
    assert [(e.analyzer, e.error_type) for e in scan.analyzer_errors] == [("broken", error_type)]


def test_dict_result_is_validated_and_merged(tmp_path: Path) -> None:
    good = {"routes": [{"path": "/plugin", "method": "GET", "file": "app.py"}]}
    scan = analyze_repository(_repo(tmp_path), analyzers=[_Bad("dicty", good)])
    assert [r.path for r in scan.routes] == ["/plugin"]
    assert scan.routes[0].source_analyzer == "dicty"
    assert scan.analyzer_errors == []


def test_error_message_is_redacted(tmp_path: Path) -> None:
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    scan = analyze_repository(_repo(tmp_path), analyzers=[_Bad("leaky", RuntimeError(f"token={secret}"))])
    assert secret not in scan.analyzer_errors[0].message


def test_strict_reraises(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="plugin bug"):
        analyze_repository(_repo(tmp_path), analyzers=[_Bad("broken", RuntimeError("plugin bug"))], strict=True)


def test_cli_reports_and_strict_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    monkeypatch.setattr(
        analyzers_mod,
        "get_registered_analyzers",
        lambda: [_Bad("broken", RuntimeError("plugin bug")), BuiltinPythonWebAnalyzer()],
    )
    runner = CliRunner()
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    flat = " ".join(_ANSI.sub("", result.output).split())
    assert "Analyzer 'broken' failed and was skipped: RuntimeError: plugin bug" in flat
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["scan"]["analyzer_errors"] == [
        {"analyzer": "broken", "error_type": "RuntimeError", "message": "plugin bug"}
    ]

    strict = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--strict-analyzers"])
    assert strict.exit_code != 0
