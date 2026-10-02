"""Whole-repo passes run once per scan, over every analyzer's merged signals (#219)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from attackmap import scanner
from attackmap.analyzers import analyze_repository
from attackmap.progress import JsonScanProgress


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/py')\n"
        "def py():\n"
        "    return request.args.get('q')\n"
    )
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/js', (req, res) => res.send(req.query.q));\n"
    )
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    return tmp_path


@pytest.fixture
def counted(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    calls: dict[str, list] = {}
    for name in ("analyze_taint", "analyze_sbom", "scan_workflows", "analyze_authz", "find_anomalies"):
        real = getattr(scanner, name)

        def wrapper(*args, _real=real, _name=name, **kwargs):
            calls.setdefault(_name, []).append(args)
            return _real(*args, **kwargs)

        monkeypatch.setattr(scanner, name, wrapper)
    return calls


def test_each_repo_pass_runs_exactly_once(tmp_path: Path, counted: dict[str, list]) -> None:
    analyze_repository(_repo(tmp_path))
    assert {name: len(c) for name, c in counted.items()} == {
        "analyze_taint": 1,
        "analyze_sbom": 1,
        "scan_workflows": 1,
        "analyze_authz": 1,
        "find_anomalies": 1,
    }


def test_repo_passes_see_merged_routes(tmp_path: Path, counted: dict[str, list]) -> None:
    analyze_repository(_repo(tmp_path))
    (merged, _root), = counted["analyze_authz"]
    paths = {r.path for r in merged.routes}
    assert {"/py", "/js"} <= paths


def test_single_done_progress_event(tmp_path: Path) -> None:
    stream = io.StringIO()
    analyze_repository(_repo(tmp_path), progress=JsonScanProgress(stream=stream))
    events = [json.loads(line)["event"] for line in stream.getvalue().splitlines() if line.strip()]
    assert events.count("done") == 1
    assert events[-1] == "done"
