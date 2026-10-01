"""``--format`` selects which report artifacts are written; ``--version``
reports the single-sourced package version."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

import attackmap
from attackmap.cli import app
from attackmap.models import AttackPath, Finding, ScanResult
from attackmap.report import write_reports

runner = CliRunner()

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)

JSON_ARTIFACTS = {
    "attackmap-report.json",
    "attackmap-report.sarif",
    "defensive-review.json",
    "review-context-pack.json",
}
MARKDOWN_ARTIFACTS = {
    "architecture.md",
    "attack-surface.md",
    "defensive-review.md",
    "attackmap-exploitability.md",
    "attackmap-paths.md",
    "attackmap-topology.md",
    "attackmap-paths.dot",
    "attackmap-topology.dot",
}


def _write(tmp_path: Path, output_format: str) -> set[str]:
    write_reports(
        tmp_path,
        ScanResult(root=".", languages=["python"], files_scanned=1),
        "# Architecture",
        "# Attack Surface",
        "# Defensive Review",
        [],
        [Finding(title="Issue", severity="medium", mitigation="m")],
        [AttackPath(name="Path", steps=["Entry: /x"], impact="Impact")],
        output_format=output_format,
    )
    return {p.name for p in tmp_path.iterdir()}


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("all", JSON_ARTIFACTS | MARKDOWN_ARTIFACTS),
        ("json", JSON_ARTIFACTS),
        ("markdown", MARKDOWN_ARTIFACTS),
    ],
)
def test_write_reports_honors_output_format(
    tmp_path: Path, output_format: str, expected: set[str]
) -> None:
    assert _write(tmp_path, output_format) == expected


def test_write_reports_rejects_unknown_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown output format"):
        _write(tmp_path, "html")


def _repo(root: Path, name: str) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "app.py").write_text(_APP, encoding="utf-8")
    return d


def test_cli_format_json_writes_only_machine_readable(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path, "solo")), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert {p.name for p in out.iterdir()} == JSON_ARTIFACTS


def test_cli_format_markdown_writes_only_human_readable(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["analyze", str(_repo(tmp_path, "solo")), "-o", str(out), "--format", "markdown"]
    )
    assert result.exit_code == 0, result.output
    assert {p.name for p in out.iterdir()} == MARKDOWN_ARTIFACTS


def test_cli_rejects_unknown_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path, "solo")), "--format", "html"])
    assert result.exit_code != 0
    assert "--format" in result.output


def test_fleet_format_json_skips_markdown_summaries(tmp_path: Path) -> None:
    out = tmp_path / "out"
    a, b = _repo(tmp_path, "svcA"), _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.json").exists()
    assert not (out / "fleet-summary.md").exists()
    assert not (out / "fleet-graph.md").exists()
    assert {p.name for p in (out / "svca").iterdir()} == JSON_ARTIFACTS


def test_fleet_format_markdown_skips_json_summary(tmp_path: Path) -> None:
    out = tmp_path / "out"
    a, b = _repo(tmp_path, "svcA"), _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out), "--format", "markdown"])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.md").exists()
    assert (out / "fleet-graph.md").exists()
    assert not (out / "fleet-summary.json").exists()


def test_version_flag_prints_package_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"attackmap {attackmap.__version__}"


def test_version_is_single_sourced() -> None:
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = pyproject["project"]
    assert "version" not in project, "version must come from attackmap.__version__ only"
    assert "version" in project["dynamic"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "attackmap.__version__"}
    assert re.fullmatch(r"\d+\.\d+\.\d+", attackmap.__version__)
