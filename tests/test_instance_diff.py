"""--fail-on-new-high catches new instances of existing findings (#222)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.fingerprint import normalize_line

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
SECRET_A = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
SECRET_B = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"

APP = """from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/report", methods=["POST"])
def report():
    subprocess.run("convert " + request.form["f"], shell=True)
    return "ok"
"""
SECOND_ROUTE = """

@app.route("/billing/export", methods=["POST"])
def export():
    subprocess.run("tar czf /tmp/x.tgz " + request.form["dir"], shell=True)
    return "ok"
"""


def _repo(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    return root


def _baseline(repo: Path, out: Path) -> Path:
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    return out / "attackmap-report.json"


def _diff(repo: Path, baseline: Path, out: Path):
    return runner.invoke(
        app,
        ["analyze", str(repo), "-o", str(out), "--format", "json", "--baseline", str(baseline), "--fail-on-new-high",
         "--diff-output", str(out / "diff.md")],
    )


def test_second_secret_in_new_file_fails_the_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"tests/fixture.py": f'KEY = "{SECRET_A}"\n'})
    base = _baseline(repo, tmp_path / "b")
    (repo / "prod").mkdir()
    (repo / "prod" / "settings.py").write_text(f'TOKEN = "{SECRET_B}"\n', encoding="utf-8")
    result = _diff(repo, base, tmp_path / "c")
    assert result.exit_code == 1, result.output
    assert "1 new instance(s)" in result.output
    md = (tmp_path / "c" / "diff.md").read_text(encoding="utf-8")
    assert "New instances of existing findings" in md and "prod/settings.py" in md


def test_second_command_injection_route_fails_the_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"app.py": APP})
    base = _baseline(repo, tmp_path / "b")
    (repo / "app.py").write_text(APP + SECOND_ROUTE, encoding="utf-8")
    result = _diff(repo, base, tmp_path / "c")
    assert result.exit_code == 1, result.output
    assert "new instance(s)" in result.output


def test_line_drift_is_not_a_new_instance(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"app.py": APP, "cfg.py": f'KEY = "{SECRET_A}"\n'})
    base = _baseline(repo, tmp_path / "b")
    # Unrelated edits above every site, plus reformatting of the sink line.
    (repo / "app.py").write_text("# header\n\n\n" + APP.replace('"convert " + request', '"convert "+request'), encoding="utf-8")
    (repo / "cfg.py").write_text(f'"""docs"""\n\n\nKEY = "{SECRET_A}"\n', encoding="utf-8")
    result = _diff(repo, base, tmp_path / "c")
    assert result.exit_code == 0, result.output
    assert "0 new, 0 new instance(s)" in result.output


def test_old_baseline_without_fingerprints_falls_back_with_a_note(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"cfg.py": f'KEY = "{SECRET_A}"\n'})
    base = _baseline(repo, tmp_path / "b")
    report = json.loads(base.read_text(encoding="utf-8"))
    for finding in report["findings"]:
        finding.pop("locations", None)
    base.write_text(json.dumps(report), encoding="utf-8")
    (repo / "more.py").write_text(f'TOKEN = "{SECRET_B}"\n', encoding="utf-8")
    result = _diff(repo, base, tmp_path / "c")
    assert result.exit_code == 0  # group-level only: the old behaviour
    assert "predates per-instance fingerprints" in " ".join(_ANSI.sub("", result.output).split())


def test_report_stores_instance_fingerprints(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"cfg.py": f'KEY = "{SECRET_A}"\n'})
    report = json.loads(_baseline(repo, tmp_path / "b").read_text(encoding="utf-8"))
    locs = [loc for f in report["findings"] for loc in f.get("locations", [])]
    assert locs and all(re.fullmatch(r"[0-9a-f]{16}", loc["fingerprint"]) for loc in locs)


def test_normalize_line_ignores_whitespace_and_literal_values() -> None:
    assert normalize_line('x = call( "a", 1 )') == normalize_line("x  =  call( 'bbb', 22 )")
    assert normalize_line("x = call(a)") != normalize_line("x = other(a)")
