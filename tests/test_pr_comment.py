"""Tests for the PR summary comment renderer (#105)."""

from __future__ import annotations

from attackmap.diff import DiffReport, FindingSnapshot
from attackmap.models import Finding
from attackmap.report import render_pr_comment


def _f(title, sev="high", exploit=None, tier=None):
    return Finding(
        title=title, severity=sev, mitigation="fix",
        exploitability=exploit, exploitability_tier=tier,
    )


def test_pr_comment_without_baseline_summarizes_severity() -> None:
    md = render_pr_comment([_f("A", "high"), _f("B", "medium"), _f("C", "low")])
    assert "AttackMap security review" in md
    assert "1 high" in md and "1 medium" in md and "1 low" in md


def test_pr_comment_with_diff_shows_new_and_gate() -> None:
    diff = DiffReport(
        new=[FindingSnapshot(id="x", title="SQL injection", severity="high", confidence="high")],
        resolved=[FindingSnapshot(id="y", title="Old thing", severity="medium", confidence="low")],
    )
    md = render_pr_comment([_f("SQL injection", "high")], diff)
    assert "1 new" in md and "1 resolved" in md
    assert "introduces new HIGH-severity findings" in md
    assert "SQL injection" in md


def test_pr_comment_no_new_high_gate_message() -> None:
    diff = DiffReport(
        new=[FindingSnapshot(id="x", title="Minor", severity="low", confidence="low")],
    )
    md = render_pr_comment([_f("Minor", "low")], diff)
    assert "no new HIGH findings" in md


def test_pr_comment_surfaces_top_exploitable() -> None:
    findings = [
        _f("eval RCE", "high", exploit=90, tier="critical"),
        _f("open redirect", "medium", exploit=40, tier="medium"),
    ]
    md = render_pr_comment(findings)
    assert "Most exploitable now" in md
    assert "90/100" in md and "CRITICAL" in md
