"""Tests for the multi-pass hunt harness — #147a N-skeptic majority verify."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.hunt_harness import (
    Hypothesis,
    combine_verdicts,
    parse_hypotheses,
    parse_verdicts,
    render_consensus_report,
    run_majority_verify,
)
from attackmap.llm_review import LlmReviewResult

runner = CliRunner()


def _v(verdict, reason="r"):
    return (verdict, reason)


# --- parse_hypotheses ------------------------------------------------------


def test_parse_hypotheses_from_marker_block() -> None:
    md = (
        "prose about leads\n"
        "=== HYPOTHESES ===\n"
        "H1: Unauth POST reaches SQL sink [evidence: surface:2, taint:1]\n"
        "H2: SSRF via req.query.url\n"
    )
    hyps = parse_hypotheses(md)
    assert [(h.id, h.title) for h in hyps] == [
        ("H1", "Unauth POST reaches SQL sink"),
        ("H2", "SSRF via req.query.url"),
    ]


def test_parse_hypotheses_dedupes_by_id() -> None:
    md = "=== HYPOTHESES ===\nH1: a\nH1: a-dupe\nH2: b\n"
    hyps = parse_hypotheses(md)
    assert [h.id for h in hyps] == ["H1", "H2"]


# --- parse_verdicts --------------------------------------------------------


def test_parse_verdicts_tolerates_formatting() -> None:
    md = (
        "VERDICT H1: CONFIRMED — concatenated at db.py:12\n"
        "VERDICT H2: REFUTED - target is a constant\n"
        "VERDICT [H3]: NEEDS REVIEW\n"
        "VERDICT H4: needs_review — lower case\n"
    )
    out = parse_verdicts(md)
    assert out["H1"][0] == "confirmed"
    assert out["H2"][0] == "refuted"
    assert out["H3"][0] == "needs_review"
    assert out["H4"][0] == "needs_review"


# --- combine_verdicts (pure) ----------------------------------------------

_HYPS = [Hypothesis("H1", "one"), Hypothesis("H2", "two")]


def test_majority_confirm_wins() -> None:
    passes = [
        {"H1": _v("confirmed"), "H2": _v("refuted")},
        {"H1": _v("confirmed"), "H2": _v("refuted")},
        {"H1": _v("refuted"), "H2": _v("refuted")},
    ]
    result = {c.id: c.verdict for c in combine_verdicts(_HYPS, passes)}
    assert result["H1"] == "confirmed"  # 2/3
    assert result["H2"] == "refuted"


def test_minority_confirm_is_refuted_lowering_false_positives() -> None:
    """A lead a single skeptic would confirm is refuted by the majority — the
    core precision win over single-vote verify (#147a)."""
    passes = [
        {"H1": _v("confirmed")},
        {"H1": _v("refuted")},
        {"H1": _v("refuted")},
    ]
    assert combine_verdicts([Hypothesis("H1", "x")], passes)[0].verdict == "refuted"


def test_tie_defaults_to_refuted() -> None:
    passes = [{"H1": _v("confirmed")}, {"H1": _v("refuted")}]  # 1-1
    assert combine_verdicts([Hypothesis("H1", "x")], passes)[0].verdict == "refuted"


def test_missing_vote_counts_as_refuted() -> None:
    passes = [{"H1": _v("confirmed")}, {}, {}]  # 2 skeptics didn't rule on it
    assert combine_verdicts([Hypothesis("H1", "x")], passes)[0].verdict == "refuted"


def test_majority_needs_review() -> None:
    passes = [
        {"H1": _v("needs_review")},
        {"H1": _v("needs_review")},
        {"H1": _v("refuted")},
    ]
    assert combine_verdicts([Hypothesis("H1", "x")], passes)[0].verdict == "needs_review"


def test_combine_is_pure_and_records_tally() -> None:
    passes = [{"H1": _v("confirmed", "why")}, {"H1": _v("confirmed", "yep")}, {"H1": _v("refuted", "no")}]
    c = combine_verdicts([Hypothesis("H1", "x")], passes)[0]
    assert (c.confirmed, c.refuted, c.needs_review) == (2, 1, 0)
    assert any("why" in r for r in c.reasons)


# --- render_consensus_report ----------------------------------------------


def test_report_groups_by_verdict_and_shows_tally() -> None:
    cons = combine_verdicts(
        _HYPS,
        [
            {"H1": _v("confirmed"), "H2": _v("refuted")},
            {"H1": _v("confirmed"), "H2": _v("refuted")},
            {"H1": _v("refuted"), "H2": _v("refuted")},
        ],
    )
    md = render_consensus_report(cons, 3)
    assert "## Confirmed (1)" in md
    assert "## Refuted (1)" in md
    assert "`H1`" in md and "2/3 confirmed" in md


# --- run_majority_verify orchestration (injected llm_call) -----------------


def _result(markdown: str) -> LlmReviewResult:
    return LlmReviewResult(
        markdown=markdown, model="claude-opus-4-8", stop_reason="end_turn",
        usage={}, backend="api",
    )


def test_run_majority_verify_lowers_false_positive_vs_single_vote() -> None:
    gen_md = "=== HYPOTHESES ===\nH1: SQLi at db.py [evidence: taint:1]\nH2: SSRF [evidence: taint:2]\n"
    # Skeptic 1 confirms H1 (a single-vote verify would ship it); skeptics 2 & 3 refute.
    skeptic_outputs = [
        "VERDICT H1: CONFIRMED — looks interpolated\nVERDICT H2: REFUTED — constant",
        "VERDICT H1: REFUTED — parameterized in excerpt\nVERDICT H2: REFUTED — constant",
        "VERDICT H1: REFUTED — bound params\nVERDICT H2: REFUTED — constant",
    ]
    calls = {"n": 0}

    def llm_call(mode, hypotheses=None):
        if mode == "hunt_generate":
            return _result(gen_md)
        out = skeptic_outputs[calls["n"]]
        calls["n"] += 1
        return _result(out)

    res = run_majority_verify(None, [], [], [], votes=3, llm_call=llm_call)
    assert res.hypothesis_count == 2
    verdicts = {c.id: c.verdict for c in res.consensus}
    assert verdicts["H1"] == "refuted"  # minority confirm → dropped
    assert verdicts["H2"] == "refuted"
    assert calls["n"] == 3  # exactly `votes` skeptic passes


def test_run_majority_verify_no_hypotheses_returns_generation() -> None:
    def llm_call(mode, hypotheses=None):
        return _result("No credible leads found.")

    res = run_majority_verify(None, [], [], [], votes=3, llm_call=llm_call)
    assert res.hypothesis_count == 0
    assert "No credible leads" in res.report


# --- CLI end-to-end --------------------------------------------------------


def _repo(tmp_path: Path) -> Path:
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


def test_cli_hunt_verify_votes_writes_consensus(tmp_path: Path, monkeypatch) -> None:
    gen_md = "=== HYPOTHESES ===\nH1: eval of request arg [evidence: taint:1]\n"

    seq = {"n": 0}

    def fake(*args, **kwargs):
        if kwargs.get("mode") == "hunt_generate":
            return _result(gen_md)
        # 3 skeptics: 2 confirm, 1 refute → consensus confirmed
        outs = [
            "VERDICT H1: CONFIRMED — eval on request arg",
            "VERDICT H1: CONFIRMED — untrusted into eval",
            "VERDICT H1: REFUTED — arg is constant",
        ]
        out = outs[min(seq["n"], len(outs) - 1)]
        seq["n"] += 1
        return _result(out)

    monkeypatch.setattr("attackmap.cli.generate_llm_review", fake)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["analyze", str(_repo(tmp_path)), "--output", str(out), "--hunt", "--verify", "--verify-votes", "3"],
    )
    assert result.exit_code == 0, result.output
    md = (out / "vulnerability-hypotheses.md").read_text(encoding="utf-8")
    assert "verified hypotheses" in md.lower()
    assert "2/3 confirmed" in md
    meta = json.loads((out / "vulnerability-hypotheses.meta.json").read_text(encoding="utf-8"))
    assert meta["verify_votes"] == 3
    assert meta["consensus"]["confirmed"] == 1


def test_cli_verify_votes_1_uses_single_pass(tmp_path: Path, monkeypatch) -> None:
    seen = {"modes": []}

    def fake(*args, **kwargs):
        seen["modes"].append(kwargs.get("mode"))
        return _result("single-pass hunt+verify output")

    monkeypatch.setattr("attackmap.cli.generate_llm_review", fake)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["analyze", str(_repo(tmp_path)), "--output", str(out), "--hunt", "--verify", "--verify-votes", "1"],
    )
    assert result.exit_code == 0, result.output
    # votes=1 → classic single hunt_verify pass, no harness modes.
    assert seen["modes"] == ["hunt_verify"]
