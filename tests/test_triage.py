"""Tests for --triage mode (#145): LLM prompt grounding + deterministic fallback."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import TRIAGE_BANNER, app
from attackmap.diff import finding_id
from attackmap.models import Finding, ScanResult
from attackmap.review_prompts import render_triage_prompts
from attackmap.triage import rank_findings, render_triage_fallback

runner = CliRunner()


def _findings() -> list[Finding]:
    return [
        Finding(title="BOLA/IDOR on modify routes", severity="high", mitigation="x",
                tags=["broken-authorization"], score=100, exploitability=82),
        Finding(title="Vulnerable dependency: lodash@4.0.0 (npm)", severity="high",
                mitigation="x", tags=["cve", "dependency"], score=100),
        Finding(title="Hardcoded secret literals found", severity="medium", mitigation="x",
                tags=["secret-exposure"], score=50),
        Finding(title="Weak password hash (MD5)", severity="low", mitigation="x",
                tags=["crypto"], score=10),
    ]


# --- Deterministic fallback ------------------------------------------------


def test_fallback_ranks_and_clusters_citing_finding_ids() -> None:
    scan = ScanResult(root="/x")
    findings = _findings()
    md = render_triage_fallback(scan, findings)
    # Every finding is cited by its stable id.
    for f in findings:
        assert finding_id(f.title) in md
    # High-severity items lead; the top item is the highest-priority finding.
    assert "Start here" in md
    assert finding_id("BOLA/IDOR on modify routes") in md.split("Start here")[1]
    # Clustered by root cause.
    assert "Authorization & access control" in md
    assert "Vulnerable dependencies" in md


def test_fallback_only_references_existing_findings() -> None:
    scan = ScanResult(root="/x")
    findings = _findings()
    md = render_triage_fallback(scan, findings)
    valid_ids = {finding_id(f.title) for f in findings}
    # Extract every backtick-quoted 16-hex id and confirm it's a real finding.
    import re
    cited = set(re.findall(r"`([0-9a-f]{16})`", md))
    assert cited
    assert cited <= valid_ids


def test_fallback_is_reproducible() -> None:
    scan = ScanResult(root="/x")
    a = render_triage_fallback(scan, _findings())
    b = render_triage_fallback(scan, list(reversed(_findings())))
    # Deterministic ordering — input order doesn't change the output.
    assert a == b


def test_fallback_dedupes_by_finding_id() -> None:
    dupe = Finding(title="BOLA/IDOR on modify routes", severity="high", mitigation="x",
                   tags=["broken-authorization"], score=100)
    ranked = rank_findings(_findings() + [dupe])
    titles = [f.title for f in ranked]
    assert titles.count("BOLA/IDOR on modify routes") == 1


def test_fallback_handles_no_findings() -> None:
    md = render_triage_fallback(ScanResult(root="/x"), [])
    assert "No heuristic findings" in md


# --- LLM prompt grounding --------------------------------------------------


def test_triage_prompt_is_grounded_and_organizational() -> None:
    scan = ScanResult(root="/x")
    rendered = render_triage_prompts(scan, [], _findings(), [])
    sys = rendered.system
    assert "do NOT find new issues" in sys or "ORGANIZE" in sys
    assert "Do NOT invent" in sys
    assert "finding_id" in sys


def test_triage_prompt_pack_includes_finding_ids() -> None:
    scan = ScanResult(root="/x")
    rendered = render_triage_prompts(scan, [], _findings(), [])
    pack = json.loads(rendered.evidence_json)
    ids = {f["finding_id"] for f in pack["findings"]}
    assert finding_id("BOLA/IDOR on modify routes") in ids


# --- CLI end-to-end --------------------------------------------------------


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    return eval(request.args['x'])\n",
        encoding="utf-8",
    )
    return repo


def test_cli_triage_deterministic_fallback(tmp_path: Path, monkeypatch) -> None:
    """With no LLM backend, --triage writes triage.md via the deterministic
    fallback rather than erroring (AC)."""
    from attackmap.llm_review import LlmReviewError

    def boom(*args, **kwargs):
        raise LlmReviewError("no backend")

    monkeypatch.setattr("attackmap.cli.generate_llm_review", boom)
    repo = _write_repo(tmp_path)
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "--output", str(out), "--triage"])
    assert result.exit_code == 0
    triage_md = (out / "triage.md").read_text(encoding="utf-8")
    assert TRIAGE_BANNER.strip().splitlines()[0] in triage_md
    assert "Deterministic prioritization" in triage_md
    meta = json.loads((out / "triage.meta.json").read_text(encoding="utf-8"))
    assert meta["backend"] == "deterministic"


def test_cli_triage_uses_llm_when_available(tmp_path: Path, monkeypatch) -> None:
    from attackmap.llm_review import LlmReviewResult

    def fake(*args, **kwargs):
        assert kwargs.get("mode") == "triage"
        return LlmReviewResult(
            markdown="## LLM triage\n1. `abc` — top thing",
            model="claude-opus-4-8",
            stop_reason="end_turn",
            usage={"input_tokens": 1, "output_tokens": 2},
            backend="api",
        )

    monkeypatch.setattr("attackmap.cli.generate_llm_review", fake)
    repo = _write_repo(tmp_path)
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "--output", str(out), "--triage"])
    assert result.exit_code == 0
    triage_md = (out / "triage.md").read_text(encoding="utf-8")
    assert "LLM triage" in triage_md
    meta = json.loads((out / "triage.meta.json").read_text(encoding="utf-8"))
    assert meta["backend"] == "api"
