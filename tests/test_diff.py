"""Tests for baseline / diff mode (#47)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.diff import (
    DiffReport,
    FindingSnapshot,
    diff_findings,
    finding_id,
    load_baseline,
    render_diff_markdown,
)
from attackmap.models import Finding


runner = CliRunner()


def _finding(title: str, severity: str = "medium", evidence: list[str] | None = None) -> Finding:
    return Finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        evidence=evidence or [f"{title} evidence"],
        mitigation="test mitigation",
        confidence="high",
    )


# ---------------------------------------------------------------------------
# finding_id — stable per-title identity
# ---------------------------------------------------------------------------


def test_finding_id_stable_across_calls() -> None:
    assert finding_id("Something bad") == finding_id("Something bad")


def test_finding_id_differs_by_title() -> None:
    assert finding_id("A") != finding_id("B")


def test_finding_id_is_hex_and_bounded() -> None:
    fid = finding_id("Anything")
    assert len(fid) == 16
    int(fid, 16)  # not-hex would raise


def test_finding_id_ignores_line_drift() -> None:
    """The whole point: same title → same id even if evidence drifts."""
    a = FindingSnapshot.from_finding(_finding("X", evidence=["file.py:1"]))
    b = FindingSnapshot.from_finding(_finding("X", evidence=["file.py:99"]))
    assert a.id == b.id


# ---------------------------------------------------------------------------
# diff_findings — set semantics
# ---------------------------------------------------------------------------


def test_new_findings_appear_only_in_current() -> None:
    baseline = [FindingSnapshot.from_finding(_finding("A"))]
    current = [FindingSnapshot.from_finding(f) for f in (_finding("A"), _finding("B"))]
    diff = diff_findings(baseline, current)
    assert [s.title for s in diff.new] == ["B"]


def test_resolved_findings_appear_only_in_baseline() -> None:
    baseline = [FindingSnapshot.from_finding(f) for f in (_finding("A"), _finding("B"))]
    current = [FindingSnapshot.from_finding(_finding("A"))]
    diff = diff_findings(baseline, current)
    assert [s.title for s in diff.resolved] == ["B"]


def test_persisted_findings_appear_in_both() -> None:
    baseline = [FindingSnapshot.from_finding(_finding("A"))]
    current = [FindingSnapshot.from_finding(_finding("A"))]
    diff = diff_findings(baseline, current)
    assert [s.title for s in diff.persisted] == ["A"]
    assert diff.new == [] and diff.resolved == []


def test_diff_counts_helper() -> None:
    diff = DiffReport(
        new=[FindingSnapshot.from_finding(_finding("N"))],
        persisted=[FindingSnapshot.from_finding(_finding("P"))],
        resolved=[FindingSnapshot.from_finding(f) for f in (_finding("R1"), _finding("R2"))],
    )
    assert diff.counts() == {"new": 1, "persisted": 1, "resolved": 2}


def test_has_new_high_triggers_only_on_new_high_findings() -> None:
    d1 = DiffReport(new=[FindingSnapshot.from_finding(_finding("H", severity="high"))])
    d2 = DiffReport(new=[FindingSnapshot.from_finding(_finding("M", severity="medium"))])
    d3 = DiffReport(persisted=[FindingSnapshot.from_finding(_finding("H", severity="high"))])
    assert d1.has_new_high is True
    assert d2.has_new_high is False
    assert d3.has_new_high is False  # a persisted HIGH is not "new"


# ---------------------------------------------------------------------------
# load_baseline — tolerant JSON parsing
# ---------------------------------------------------------------------------


def test_load_baseline_from_full_report_shape(tmp_path: Path) -> None:
    report = {
        "findings": [
            {"title": "A", "severity": "high", "confidence": "high", "evidence": ["e1"], "mitigation": "m", "tags": []},
            {"title": "B", "severity": "medium", "confidence": "medium", "evidence": ["e2"], "mitigation": "m", "tags": ["t"]},
        ]
    }
    p = tmp_path / "prev.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    snapshots = load_baseline(p)
    assert {s.title for s in snapshots} == {"A", "B"}


def test_load_baseline_from_bare_finding_list(tmp_path: Path) -> None:
    p = tmp_path / "prev.json"
    p.write_text(json.dumps([{"title": "A", "severity": "high", "confidence": "high"}]), encoding="utf-8")
    snapshots = load_baseline(p)
    assert len(snapshots) == 1
    assert snapshots[0].title == "A"


def test_load_baseline_missing_findings_key_yields_empty(tmp_path: Path) -> None:
    p = tmp_path / "prev.json"
    p.write_text(json.dumps({"scan": {}, "attack_surfaces": []}), encoding="utf-8")
    assert load_baseline(p) == []


# ---------------------------------------------------------------------------
# render_diff_markdown
# ---------------------------------------------------------------------------


def test_diff_markdown_contains_all_three_sections() -> None:
    baseline = [FindingSnapshot.from_finding(_finding("gone", severity="low"))]
    current = [
        FindingSnapshot.from_finding(_finding("kept", severity="medium")),
        FindingSnapshot.from_finding(_finding("brand new", severity="high")),
    ]
    md = render_diff_markdown(diff_findings(baseline, current))
    assert "## New findings" in md
    assert "## Resolved findings" in md
    assert "## Persisted findings" in md
    assert "brand new" in md
    assert "kept" in md
    assert "gone" in md
    # Severity chip on each finding line.
    assert "**[HIGH]**" in md
    assert "**[MEDIUM]**" in md


def test_diff_markdown_empty_sections_say_none() -> None:
    md = render_diff_markdown(DiffReport())
    assert md.count("_none_") == 3


def test_diff_markdown_sorts_by_severity_then_title() -> None:
    diff = DiffReport(
        new=[
            FindingSnapshot.from_finding(_finding("zebra", severity="low")),
            FindingSnapshot.from_finding(_finding("alpha", severity="high")),
        ]
    )
    md = render_diff_markdown(diff)
    # HIGH should appear before LOW.
    assert md.index("alpha") < md.index("zebra")


# ---------------------------------------------------------------------------
# CLI wiring: --baseline / --diff-output / --fail-on-new-high
# ---------------------------------------------------------------------------


def _write_baseline(tmp_path: Path, findings: list[dict]) -> Path:
    p = tmp_path / "prev.json"
    p.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return p


def _tiny_repo(tmp_path: Path) -> Path:
    """Minimal repo that will produce at least the weak-signal finding."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "readme.md").write_text("hello\n", encoding="utf-8")
    return repo


def test_cli_baseline_writes_diff_markdown(tmp_path: Path) -> None:
    repo = _tiny_repo(tmp_path)
    out = tmp_path / "reports"
    baseline = _write_baseline(tmp_path, [{"title": "Old Finding", "severity": "medium", "confidence": "medium"}])
    result = runner.invoke(
        app,
        ["analyze", str(repo), "--output", str(out), "--baseline", str(baseline)],
    )
    assert result.exit_code == 0, result.stdout
    diff_md = (out / "attackmap-diff.md").read_text(encoding="utf-8")
    assert "AttackMap diff" in diff_md
    assert "Old Finding" in diff_md  # resolved


def test_cli_custom_diff_output(tmp_path: Path) -> None:
    repo = _tiny_repo(tmp_path)
    out = tmp_path / "reports"
    diff_path = tmp_path / "elsewhere" / "diff.md"
    baseline = _write_baseline(tmp_path, [])
    result = runner.invoke(
        app,
        [
            "analyze",
            str(repo),
            "--output",
            str(out),
            "--baseline",
            str(baseline),
            "--diff-output",
            str(diff_path),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert diff_path.exists()
    # And the default location should NOT have been used.
    assert not (out / "attackmap-diff.md").exists()


def test_cli_fail_on_new_high_exits_nonzero_when_new_high(tmp_path: Path) -> None:
    """Empty baseline + any HIGH in current → gate fires.

    Admin routes + a cross-file eval sink are two reliable HIGH triggers
    in the built-in ruleset; using both keeps the test resilient to
    single-rule changes.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\n"
        "from worker import run\n"
        "app = Flask(__name__)\n"
        "@app.route('/admin/users', methods=['DELETE'])\n"
        "def delete_user():\n"
        "    return run(request.get_json())\n",
        encoding="utf-8",
    )
    (repo / "worker.py").write_text(
        "def run(payload):\n    return eval(payload['expr'])\n",
        encoding="utf-8",
    )
    out = tmp_path / "reports"
    baseline = _write_baseline(tmp_path, [])
    result = runner.invoke(
        app,
        [
            "analyze",
            str(repo),
            "--output",
            str(out),
            "--baseline",
            str(baseline),
            "--fail-on-new-high",
        ],
    )
    # Non-zero exit signals the gate fired.
    assert result.exit_code != 0
    assert "New HIGH findings introduced" in result.stdout + result.stderr


def test_cli_fail_on_new_high_ok_when_no_new_high(tmp_path: Path) -> None:
    """Trivial repo: no HIGH findings → gate passes."""
    repo = _tiny_repo(tmp_path)
    out = tmp_path / "reports"
    baseline = _write_baseline(tmp_path, [])
    result = runner.invoke(
        app,
        [
            "analyze",
            str(repo),
            "--output",
            str(out),
            "--baseline",
            str(baseline),
            "--fail-on-new-high",
        ],
    )
    assert result.exit_code == 0, result.stdout


def test_cli_fail_on_new_high_without_baseline_errors(tmp_path: Path) -> None:
    """Invalid flag combo — should fail early, before running analyze.

    We don't inspect the specific error text since Typer/Click formats
    BadParameter messages with a Rich panel + line-wrapping that varies
    across versions; exit code + no report directory is enough proof.
    """
    repo = _tiny_repo(tmp_path)
    out = tmp_path / "r"
    result = runner.invoke(
        app,
        ["analyze", str(repo), "--output", str(out), "--fail-on-new-high"],
    )
    assert result.exit_code != 0
    # BadParameter fires before analyze runs → no report dir created.
    assert not (out / "attackmap-report.json").exists()


def test_cli_baseline_missing_file_errors(tmp_path: Path) -> None:
    repo = _tiny_repo(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            str(repo),
            "--output",
            str(tmp_path / "r"),
            "--baseline",
            str(tmp_path / "does-not-exist.json"),
        ],
    )
    assert result.exit_code != 0


def test_json_report_findings_carry_stable_id(tmp_path: Path) -> None:
    """attackmap-report.json findings should carry the same id we'd
    compute independently — so downstream tooling can trust the field."""
    from attackmap.diff import finding_id as compute_id

    repo = _tiny_repo(tmp_path)
    out = tmp_path / "reports"
    result = runner.invoke(app, ["analyze", str(repo), "--output", str(out)])
    assert result.exit_code == 0
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    for f in report["findings"]:
        assert "id" in f
        assert f["id"] == compute_id(f["title"])


def test_baseline_round_trip_via_current_report(tmp_path: Path) -> None:
    """Run once, use its report as the baseline for a second run; both
    findings sets should match → all persisted, none new/resolved."""
    repo = _tiny_repo(tmp_path)
    out1 = tmp_path / "r1"
    out2 = tmp_path / "r2"
    r1 = runner.invoke(app, ["analyze", str(repo), "--output", str(out1)])
    assert r1.exit_code == 0
    r2 = runner.invoke(
        app,
        [
            "analyze",
            str(repo),
            "--output",
            str(out2),
            "--baseline",
            str(out1 / "attackmap-report.json"),
        ],
    )
    assert r2.exit_code == 0, r2.stdout
    diff_md = (out2 / "attackmap-diff.md").read_text(encoding="utf-8")
    assert "**0 new**" in diff_md
    assert "**0 resolved**" in diff_md
