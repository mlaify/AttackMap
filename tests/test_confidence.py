"""Unified confidence scale and --min-confidence (#198)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.confidence import filter_by_confidence, normalize_confidence
from attackmap.models import Finding
from attackmap.schemas import report_schema


def _f(confidence: str, tags: list[str] | None = None) -> Finding:
    return Finding(title=f"t-{confidence}", severity="high", mitigation="-", confidence=confidence, tags=tags or [])


def test_leads_are_low_confidence() -> None:
    findings = [_f("high", ["speculative"]), _f("medium", ["needs-review"]), _f("high", ["taint-chain"])]
    normalize_confidence(findings)
    assert [f.confidence for f in findings] == ["low", "low", "high"]


def test_filter_by_confidence() -> None:
    findings = [_f("low"), _f("medium"), _f("high")]
    assert [f.confidence for f in filter_by_confidence(findings, "medium")[0]] == ["medium", "high"]
    assert filter_by_confidence(findings, "high")[1] == 2


def test_cli_min_confidence_filters_every_output(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\nimport sqlite3, random\napp = Flask(__name__)\n"
        "@app.route('/search')\ndef search():\n"
        "    return sqlite3.connect('d').execute('SELECT * FROM t WHERE n = ' + request.args['q']).fetchall()\n"
    )
    runner = CliRunner()
    assert runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "all")]).exit_code == 0
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "high"), "--min-confidence", "HIGH"])
    assert result.exit_code == 0, result.output
    every = json.loads((tmp_path / "all" / "attackmap-report.json").read_text())
    high = json.loads((tmp_path / "high" / "attackmap-report.json").read_text())
    assert "confidence_filter" not in every
    assert {f["confidence"] for f in high["findings"]} <= {"high"}
    assert high["confidence_filter"] == {"min_confidence": "high", "filtered": len(every["findings"]) - len(high["findings"])}
    assert high["confidence_filter"]["filtered"] > 0
    jsonschema.validate(high, report_schema())
    sarif = json.loads((tmp_path / "high" / "attackmap-report.sarif").read_text())
    kept_rules = {f["rule_id"] for f in high["findings"]}
    assert {r["ruleId"] for r in sarif["runs"][0]["results"] if r.get("kind") != "informational"} <= kept_rules
    assert runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "x"), "--min-confidence", "sure"]).exit_code != 0
