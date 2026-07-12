"""Tests for finding suppression (#144)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import sarif
from attackmap.cli import app
from attackmap.diff import FindingSnapshot, diff_findings, finding_id
from attackmap.models import Finding
from attackmap.suppress import (
    INLINE_DIRECTIVE,
    Suppression,
    SuppressionSet,
    apply_suppressions,
    collect_suppressions,
    rule_slug,
    scan_inline_suppressions,
)

runner = CliRunner()
_SECRET_RULE = "hard-coded-secret-literals-were-found-in-source-or-config"


def _secret_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "config.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    return repo


def _finding(
    title: str, severity: str = "high", evidence: list[str] | None = None
) -> Finding:
    return Finding(
        title=title,
        severity=severity,  # type: ignore[arg-type]
        evidence=evidence or [],
        mitigation="do the thing",
        confidence="high",
    )


# ---------------------------------------------------------------------------
# rule_slug — must equal the SARIF ruleId so users key on the same string
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "Hardcoded secret literals",
        "Unauthenticated webhook (no auth)!",
        "Open   redirect / SSRF",
        "",
    ],
)
def test_rule_slug_matches_sarif_ruleid(title: str) -> None:
    assert rule_slug(title) == sarif._slugify(title)


def test_rule_slug_is_stable_and_slugified() -> None:
    assert rule_slug("Hardcoded secret literals") == "hardcoded-secret-literals"
    assert rule_slug("!!!") == "finding"


# ---------------------------------------------------------------------------
# SuppressionSet.match — id / rule / path
# ---------------------------------------------------------------------------


def test_match_by_id() -> None:
    f = _finding("Open redirect")
    ss = SuppressionSet([Suppression(reason="accepted", id=finding_id("Open redirect"))])
    assert ss.match(f)
    assert not ss.match(_finding("Different title"))


def test_match_by_rule_covers_all_titles_of_that_rule() -> None:
    ss = SuppressionSet([Suppression(reason="fixtures", rule="hardcoded-secret-literals")])
    assert ss.match(_finding("Hardcoded secret literals", evidence=["K in a.py"]))
    assert not ss.match(_finding("Open redirect", evidence=["K in a.py"]))


def test_path_suppression_requires_full_containment() -> None:
    contained = _finding(
        "Hardcoded secret literals",
        evidence=["API_KEY in tests/fixtures/a.py", "TOKEN in tests/fixtures/b.py"],
    )
    escapes = _finding(
        "Hardcoded secret literals",
        evidence=["API_KEY in tests/fixtures/a.py", "TOKEN in src/live.py"],
    )
    ss = SuppressionSet([Suppression(reason="fixtures", path="tests/fixtures/**")])
    assert ss.match(contained)
    assert not ss.match(escapes), "a finding touching live code must not be hidden"


def test_path_suppression_needs_a_citable_path() -> None:
    # No extractable file path in evidence → path selector can't match.
    f = _finding("Some heuristic", evidence=["confidence=0.90", "3 occurrences"])
    ss = SuppressionSet([Suppression(reason="x", path="**")])
    assert not ss.match(f)


def test_rule_scoped_path_only_matches_that_rule() -> None:
    ss = SuppressionSet(
        [Suppression(reason="x", rule="open-redirect", path="vendor/**")]
    )
    other = _finding("Hardcoded secret literals", evidence=["K in vendor/x.py"])
    same = _finding("Open redirect", evidence=["GET /r in vendor/x.py"])
    assert not ss.match(other)
    assert ss.match(same)


def test_glob_star_spans_path_separators() -> None:
    f = _finding("X", evidence=["a in vendor/deep/nested/mod.py"])
    assert SuppressionSet([Suppression(reason="x", path="vendor/*")]).match(f)
    assert SuppressionSet([Suppression(reason="x", path="vendor/**")]).match(f)


# ---------------------------------------------------------------------------
# apply_suppressions — partitioning + the diff gate
# ---------------------------------------------------------------------------


def test_apply_partitions_active_and_suppressed() -> None:
    a = _finding("Hardcoded secret literals", evidence=["K in tests/fixtures/a.py"])
    b = _finding("Open redirect", evidence=["GET /r in src/app.py"])
    ss = SuppressionSet([Suppression(reason="fixtures only", path="tests/fixtures/**")])
    out = apply_suppressions([a, b], ss)
    assert [f.title for f in out.active] == ["Open redirect"]
    assert [s.rule for s in out.suppressed] == ["hardcoded-secret-literals"]
    assert out.suppressed[0].reason == "fixtures only"
    assert out.count == 1


def test_suppressed_high_does_not_trip_fail_on_new_high() -> None:
    suppressed_high = _finding(
        "Hardcoded secret literals", severity="high", evidence=["K in tests/fixtures/a.py"]
    )
    ss = SuppressionSet([Suppression(reason="fixtures", path="tests/fixtures/**")])
    out = apply_suppressions([suppressed_high], ss)
    current = [FindingSnapshot.from_finding(f) for f in out.active]
    diff = diff_findings([], current)
    assert diff.has_new_high is False, "suppressed HIGH must not count as new"


def test_unsuppressed_findings_are_unaffected() -> None:
    f = _finding("Open redirect", severity="high", evidence=["GET /r in src/app.py"])
    out = apply_suppressions([f], SuppressionSet([]))
    assert out.active == [f]
    assert out.suppressed == []


# ---------------------------------------------------------------------------
# SARIF — suppressed findings retained + marked
# ---------------------------------------------------------------------------


def test_sarif_marks_suppressed_and_keeps_active_clean() -> None:
    active = _finding("Open redirect", evidence=["GET /r in src/app.py"])
    supp = _finding("Hardcoded secret literals", evidence=["K in tests/fixtures/a.py"])
    log = sarif.build_sarif([active], [], suppressed=[(supp, "fixtures only")])
    results = log["runs"][0]["results"]
    assert len(results) == 2
    suppressed_results = [r for r in results if "suppressions" in r]
    active_results = [r for r in results if "suppressions" not in r]
    assert len(suppressed_results) == 1
    assert len(active_results) == 1
    assert suppressed_results[0]["suppressions"][0]["justification"] == "fixtures only"
    # The rule for a suppressed finding still resolves in the taxonomy.
    rule_ids = {rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]}
    assert "hardcoded-secret-literals" in rule_ids


# ---------------------------------------------------------------------------
# Loading — YAML baseline + inline directives
# ---------------------------------------------------------------------------


def test_inline_directive_regex_shapes() -> None:
    m = INLINE_DIRECTIVE.search("k = 1  # attackmap:ignore[rule-a, rule-b] reason text")
    assert m and m.group(1) == "rule-a, rule-b" and m.group(2) == "reason text"
    m = INLINE_DIRECTIVE.search("x // attackmap:ignore bare")
    assert m and m.group(1) is None and m.group(2) == "bare"


def test_scan_inline_suppressions(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        'API_KEY = "xxx"  # attackmap:ignore[hardcoded-secret-literals] staging key\n',
        encoding="utf-8",
    )
    f = _finding("Hardcoded secret literals", evidence=["API_KEY in src/app.py"])
    sups = scan_inline_suppressions(tmp_path, [f])
    assert len(sups) == 1
    assert sups[0].rule == "hardcoded-secret-literals"
    assert sups[0].path == "src/app.py"
    assert sups[0].origin == "inline"
    assert SuppressionSet(sups).match(f)


def test_inline_only_reads_cited_files(tmp_path: Path) -> None:
    # A directive in a file NOT cited by any finding is never read/applied.
    (tmp_path / "unrelated.py").write_text(
        "x = 1  # attackmap:ignore[open-redirect] noise\n", encoding="utf-8"
    )
    f = _finding("Open redirect", evidence=["GET /r in src/app.py"])
    assert scan_inline_suppressions(tmp_path, [f]) == []


def test_load_yaml_baseline_list_and_mapping(tmp_path: Path) -> None:
    accepted_id = finding_id("Accepted title")
    (tmp_path / ".attackmap-suppress.yaml").write_text(
        "version: 1\n"
        "suppress:\n"
        f"  - id: {accepted_id}\n"
        "    reason: accepted risk\n"
        "  - rule: hardcoded-secret-literals\n"
        "    reason: test fixtures\n"
        "    paths:\n"
        "      - tests/fixtures/**\n"
        "  - path: vendor/**\n"
        "    reason: third party\n",
        encoding="utf-8",
    )
    suppset, warnings = collect_suppressions(tmp_path, [], enable_inline=False)
    assert warnings == []
    # id entry matches exactly that finding
    assert suppset.match(_finding("Accepted title", evidence=["x in live.py"]))
    # rule+path entry suppresses a contained secret finding
    contained = _finding("Hardcoded secret literals", evidence=["K in tests/fixtures/a.py"])
    assert suppset.match(contained)
    # path-only entry
    vendored = _finding("Any finding", evidence=["x in vendor/lib/mod.py"])
    assert suppset.match(vendored)


def test_load_yaml_skips_entries_without_reason_or_selector(tmp_path: Path) -> None:
    (tmp_path / ".attackmap-suppress.yaml").write_text(
        "suppress:\n"
        "  - rule: no-reason-here\n"  # missing reason → skipped w/ warning
        "  - reason: no selector here\n",  # missing selector → skipped w/ warning
        encoding="utf-8",
    )
    suppset, warnings = collect_suppressions(tmp_path, [], enable_inline=False)
    assert len(warnings) == 2
    assert not suppset.match(_finding("no-reason-here", evidence=["x in a.py"]))


def test_missing_baseline_is_a_no_op(tmp_path: Path) -> None:
    suppset, warnings = collect_suppressions(tmp_path, [_finding("X")], enable_inline=True)
    assert warnings == []
    assert not suppset.match(_finding("X", evidence=["x in a.py"]))


# ---------------------------------------------------------------------------
# End-to-end CLI — the acceptance criteria through `attackmap analyze`
# ---------------------------------------------------------------------------


def _run(repo: Path, out: Path, *extra: str):
    return runner.invoke(
        app,
        ["analyze", str(repo), "--output", str(out), "--no-progress", *extra],
    )


def test_cli_unsuppressed_high_trips_the_gate(tmp_path: Path) -> None:
    repo = _secret_repo(tmp_path)
    out = tmp_path / "out"
    baseline = tmp_path / "baseline.json"
    baseline.write_text("[]", encoding="utf-8")
    result = _run(repo, out, "--baseline", str(baseline), "--fail-on-new-high")
    assert result.exit_code == 1, result.stdout
    report = json.loads((out / "attackmap-report.json").read_text())
    assert any(f["title"].startswith("Hard-coded secret") for f in report["findings"])
    assert report["suppressed_findings"] == []


def test_cli_baseline_file_suppresses_and_clears_gate(tmp_path: Path) -> None:
    repo = _secret_repo(tmp_path)
    out = tmp_path / "out"
    baseline = tmp_path / "baseline.json"
    baseline.write_text("[]", encoding="utf-8")
    (repo / ".attackmap-suppress.yaml").write_text(
        "suppress:\n"
        f"  - rule: {_SECRET_RULE}\n"
        "    reason: example key in a doc, not real\n",
        encoding="utf-8",
    )
    result = _run(repo, out, "--baseline", str(baseline), "--fail-on-new-high")
    assert result.exit_code == 0, result.stdout
    assert "Suppressed 1 finding" in result.stdout
    report = json.loads((out / "attackmap-report.json").read_text())
    assert not any(f["title"].startswith("Hard-coded secret") for f in report["findings"])
    assert len(report["suppressed_findings"]) == 1
    assert report["suppressed_findings"][0]["reason"] == "example key in a doc, not real"
    # SARIF: retained + marked suppressed.
    sarif_log = json.loads((out / "attackmap-report.sarif").read_text())
    results = sarif_log["runs"][0]["results"]
    suppressed = [r for r in results if "suppressions" in r]
    assert len(suppressed) == 1


def test_cli_inline_directive_suppresses(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "config.py").write_text(
        f'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # attackmap:ignore[{_SECRET_RULE}] doc example\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = _run(repo, out)
    assert result.exit_code == 0, result.stdout
    report = json.loads((out / "attackmap-report.json").read_text())
    assert not any(f["title"].startswith("Hard-coded secret") for f in report["findings"])
    assert len(report["suppressed_findings"]) == 1
    assert report["suppressed_findings"][0]["reason"] == "doc example"


def test_cli_no_suppress_flag_disables_suppression(tmp_path: Path) -> None:
    repo = _secret_repo(tmp_path)
    (repo / ".attackmap-suppress.yaml").write_text(
        f"suppress:\n  - rule: {_SECRET_RULE}\n    reason: silence\n", encoding="utf-8"
    )
    out = tmp_path / "out"
    result = _run(repo, out, "--no-suppress")
    assert result.exit_code == 0, result.stdout
    report = json.loads((out / "attackmap-report.json").read_text())
    assert any(f["title"].startswith("Hard-coded secret") for f in report["findings"])
    assert report["suppressed_findings"] == []
