"""Tests for multi-repo fleet mode (#146a)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.fleet import (
    FleetRepoResult,
    FleetScan,
    fleet_repo_ids,
    fleet_summary_json,
    render_fleet_summary,
)
from attackmap.models import Finding, ScanResult

runner = CliRunner()


def _finding(title: str, severity: str) -> Finding:
    return Finding(title=title, severity=severity, mitigation="x")


def _result(repo_id: str, findings: list[Finding]) -> FleetRepoResult:
    return FleetRepoResult(
        repo_id=repo_id,
        root=f"/repos/{repo_id}",
        report_dir=f"/out/{repo_id}",
        scan=ScanResult(root=f"/repos/{repo_id}"),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# repo id disambiguation
# ---------------------------------------------------------------------------


def test_fleet_repo_ids_slugifies_and_disambiguates() -> None:
    ids = fleet_repo_ids(
        [Path("/a/My Service"), Path("/b/my-service"), Path("/c/service")]
    )
    assert ids == ["my-service", "my-service-2", "service"]


def test_fleet_repo_ids_stable_and_unique() -> None:
    ids = fleet_repo_ids([Path("/x/api"), Path("/y/api"), Path("/z/api")])
    assert ids == ["api", "api-2", "api-3"]
    assert len(set(ids)) == 3


def test_fleet_repo_ids_unique_against_preexisting_suffix() -> None:
    # `api`, `api`, `api-2`: the disambiguated 2nd (`api-2`) must not collide
    # with the 3rd input's own name — else reports overwrite each other.
    ids = fleet_repo_ids([Path("/x/api"), Path("/y/api"), Path("/z/api-2")])
    assert len(set(ids)) == 3
    assert ids == ["api", "api-2", "api-2-2"]


# ---------------------------------------------------------------------------
# summary rendering
# ---------------------------------------------------------------------------


def test_render_fleet_summary_counts_by_severity() -> None:
    fleet = FleetScan(
        results=[
            _result("svc-a", [_finding("SQLi", "high"), _finding("weak-tls", "medium")]),
            _result("svc-b", [_finding("info", "low")]),
        ]
    )
    md = render_fleet_summary(fleet)
    assert "2 repositories analyzed · 3 finding(s) total." in md
    assert "| `svc-a` | 1 | 1 | 0 | 2 |" in md
    assert "| `svc-b` | 0 | 0 | 1 | 1 |" in md
    assert "[svc-a/](svc-a/)" in md
    assert "SQLi" in md  # top findings listed


def test_fleet_summary_json_shape() -> None:
    fleet = FleetScan(results=[_result("svc-a", [_finding("SQLi", "high")])])
    data = fleet_summary_json(fleet)
    assert data["repo_count"] == 1
    assert data["total_findings"] == 1
    repo = data["repos"][0]
    assert repo["repo_id"] == "svc-a"
    assert repo["severity_counts"] == {"high": 1, "medium": 0, "low": 0}


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

_APP = """\
from flask import Flask, request
app = Flask(__name__)


@app.route("/x")
def x():
    return request.args["q"]
"""


def _repo(root: Path, name: str, body: str = _APP) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "app.py").write_text(body, encoding="utf-8")
    return d


def test_single_repo_writes_reports_flat_no_fleet_summary(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "solo")
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out)])
    assert result.exit_code == 0, result.output
    # Single-repo path is unchanged: reports land flat, no fleet artifacts.
    assert (out / "attackmap-report.json").exists()
    assert not (out / "fleet-summary.md").exists()


def test_multi_repo_writes_per_repo_dirs_and_fleet_summary(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.md").exists()
    assert (out / "fleet-summary.json").exists()
    assert (out / "svca" / "attackmap-report.json").exists()
    assert (out / "svcb" / "attackmap-report.json").exists()
    assert "2 repositories" in result.output


def test_multi_repo_rejects_single_repo_only_flags(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "--hunt"])
    assert result.exit_code != 0
    assert "multi-repo mode" in result.output


def test_multi_repo_missing_path_errors(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    result = runner.invoke(app, ["analyze", str(a), str(tmp_path / "nope")])
    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_multi_repo_validates_progress_format(tmp_path: Path) -> None:
    # --progress-format is validated before the fleet branch, same as single-repo.
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(
        app, ["analyze", str(a), str(b), "--progress-format", "bogus", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code != 0
    assert "--progress-format must be one of" in result.output
