"""Repo-derived text can't inject Markdown into AttackMap's outputs (#233, part B)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.defensive_review import render_defensive_review
from attackmap.diff import DiffReport, FindingSnapshot, render_diff_markdown
from attackmap.md import md_code, md_text, sanitize_llm_markdown
from attackmap.models import AttackPath, AttackSurface, Finding, ScanResult
from attackmap.report import render_pr_comment
from attackmap.sarif import build_sarif

HOSTILE = "/x](https://evil.example/login) <img src=https://evil.example/p.png> @org/security-team ‮gnp.exe ` "


_CODE_SPAN = re.compile(r"(`+)(.+?)\1")


def _assert_inert(markdown: str) -> None:
    """None of the hostile constructs would render: outside code spans every
    link/HTML/mention/autolink is escaped or broken; bidi is never raw."""
    assert "\u202e" not in markdown  # bidi override shown escaped, never applied
    prose = _CODE_SPAN.sub("", markdown)
    assert not re.search(r"(?<!\\)\]\(", prose), "live Markdown link"
    assert not re.search(r"(?<!\\)<(?!/?sub>)[A-Za-z!/]", prose), "raw HTML"
    assert not re.search(r"(?<![\w;])@[A-Za-z]", prose), "live @mention"
    assert "https://evil" not in prose, "live autolink"


def _hostile_finding() -> Finding:
    return Finding(
        title=f"Vulnerable dependency: {HOSTILE}@1.0 (pypi)",
        severity="high",
        mitigation="Upgrade.",
        evidence=[f"app.py:3 — @app.post('{HOSTILE}')"],
        exploitability=90,
        exploitability_tier="critical",
    )


def test_md_text_neutralizes_every_construct() -> None:
    out = md_text(HOSTILE)
    assert "\\]\\(" in out and "\\<img" in out
    assert "@&#8203;org" in out
    assert "https:&#8203;//evil" in out
    assert "\\u202e" in out
    assert "\n" not in md_text("a\nb")


@pytest.mark.parametrize("value", ["plain", "has `tick`", "``double``", "`edge", HOSTILE])
def test_md_code_fence_cannot_be_closed_early(value: str) -> None:
    span = md_code(value)
    fence = re.match(r"`+", span).group(0)
    inner = span[len(fence) : -len(fence)]
    assert fence not in inner
    assert span.endswith(fence)


def test_pr_comment_is_inert() -> None:
    finding = _hostile_finding()
    snapshot = FindingSnapshot.from_finding(finding)
    _assert_inert(render_pr_comment([finding], DiffReport(new=[snapshot])))
    _assert_inert(render_pr_comment([finding]))


def test_diff_markdown_is_inert() -> None:
    snapshot = FindingSnapshot.from_finding(_hostile_finding())
    md = render_diff_markdown(DiffReport(new=[snapshot]))
    _assert_inert(md)
    assert "`" in md  # evidence rendered as a code span


def test_sarif_markdown_is_inert() -> None:
    sarif = build_sarif([_hostile_finding()], [])
    for run in sarif["runs"]:
        for result in run["results"]:
            _assert_inert(result["message"]["markdown"])


def test_defensive_review_is_inert() -> None:
    scan = ScanResult(root=".", languages=["python"], files_scanned=1)
    surface = AttackSurface(
        route=HOSTILE, method="POST", file="app.py", category="admin", exposure="public", risk="high",
        auth_signals=[], data_store_interaction=True,
    )
    path = AttackPath(name=f"Path via {HOSTILE}", steps=[f"Entry: {HOSTILE}"], impact="x")
    _assert_inert(render_defensive_review(scan, [surface], [_hostile_finding()], [path]))


def test_llm_markdown_is_defanged() -> None:
    llm = (
        "## Review\n\nSee [the fix](https://evil.example/phish) and ![x](https://evil.example/p.png)\n"
        "<script>alert(1)</script><details><summary>hidden</summary>buried</details>\n"
        "cc @org/security-team — visit https://evil.example\n- keep **this** `code`\n"
    )
    out = sanitize_llm_markdown(llm)
    assert "<script>" not in out and "<details>" not in out
    assert "the fix (https:&#8203;//evil.example/phish)" in out
    assert "[image removed: x]" in out
    assert "@&#8203;org" in out
    assert "## Review" in out and "**this**" in out and "`code`" in out


def test_end_to_end_pr_comment_and_review(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n\n"
        f"@app.route({json.dumps(HOSTILE)}, methods=['POST'])\n"
        "def admin():\n    subprocess.run(request.args['c'], shell=True)\n    return 'ok'\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app, ["analyze", str(repo), "-o", str(out), "--pr-comment", str(out / "pr-comment.md")]
    )
    assert result.exit_code == 0, result.output
    for name in ("pr-comment.md", "defensive-review.md"):
        _assert_inert((out / name).read_text(encoding="utf-8"))
