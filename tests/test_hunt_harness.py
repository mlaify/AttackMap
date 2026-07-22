"""Tests for the multi-pass hunt harness — #147a N-skeptic majority verify."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.hunt_harness import (
    Hypothesis,
    combine_verdicts,
    dedupe_hypotheses,
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
    assert any("why" in reason for _verdict, reason in c.reasons)


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


def test_parse_hypotheses_retains_cited_evidence() -> None:
    md = "=== HYPOTHESES ===\nH1: SQLi at db.py [evidence: surface:2, taint:1]\n"
    h = parse_hypotheses(md)[0]
    assert h.title == "SQLi at db.py"
    assert h.evidence == "surface:2, taint:1"


def test_report_quotes_reason_matching_consensus_verdict() -> None:
    # First skeptic dissents (refuted), majority confirms — the shown reason
    # must agree with the CONFIRMED consensus, not the dissent.
    cons = combine_verdicts(
        [Hypothesis("H1", "x")],
        [
            {"H1": _v("refuted", "looked parameterized")},
            {"H1": _v("confirmed", "clearly interpolated")},
            {"H1": _v("confirmed", "untrusted into query")},
        ],
    )
    md = render_consensus_report(cons, 3)
    assert "## Confirmed (1)" in md
    assert "clearly interpolated" in md or "untrusted into query" in md
    assert "looked parameterized" not in md


def test_needs_review_majority_is_needs_review_not_confirmed() -> None:
    passes = [{"H1": _v("needs_review")}, {"H1": _v("needs_review")}, {"H1": _v("confirmed")}]
    assert combine_verdicts([Hypothesis("H1", "x")], passes)[0].verdict == "needs_review"


def test_run_majority_verify_aggregates_usage_and_passes_evidence() -> None:
    gen_md = "=== HYPOTHESES ===\nH1: SQLi [evidence: taint:1]\n"
    seen_evidence = []

    def llm_call(mode, hypotheses=None):
        if mode == "hunt_generate":
            return LlmReviewResult(markdown=gen_md, model="m", stop_reason=None,
                                   usage={"input_tokens": 10, "output_tokens": 5}, backend="api")
        seen_evidence.append(hypotheses[0]["evidence"])
        return LlmReviewResult(markdown="VERDICT H1: REFUTED — no", model="m", stop_reason=None,
                               usage={"input_tokens": 3, "output_tokens": 2}, backend="api")

    res = run_majority_verify(None, [], [], [], votes=2, llm_call=llm_call)
    # gen (10/5) + 2 skeptics (3/2 each) = 16 input, 9 output.
    assert res.usage == {"input_tokens": 16, "output_tokens": 9}
    # Every skeptic received the cited evidence ids, not just a bare title.
    assert seen_evidence == ["taint:1", "taint:1"]


def test_run_majority_verify_no_hypotheses_returns_generation() -> None:
    def llm_call(mode, hypotheses=None):
        return _result("No credible leads found.")

    res = run_majority_verify(None, [], [], [], votes=3, llm_call=llm_call)
    assert res.hypothesis_count == 0
    assert "No credible leads" in res.report


# --- cross-pass dedupe (#147b) --------------------------------------------


def test_dedupe_merges_restatements_and_keeps_unique() -> None:
    lens_a = [
        Hypothesis("H1", "SQL injection at db.py via order id", evidence="taint:1", lenses=("auth-bypass",)),
        Hypothesis("H2", "Missing auth on /admin", evidence="surface:5", lenses=("auth-bypass",)),
    ]
    lens_b = [
        Hypothesis("H1", "SQL injection reaches db.py order id", evidence="taint:1", lenses=("deserialization",)),
        Hypothesis("H2", "Unsafe pickle load of session", evidence="taint:9", lenses=("deserialization",)),
    ]
    merged = dedupe_hypotheses([lens_a, lens_b])
    titles = [h.title for h in merged]
    assert len(merged) == 3  # the two SQLi restatements collapsed
    assert [h.id for h in merged] == ["H1", "H2", "H3"]  # freshly re-numbered
    # The merged SQLi lead carries both lenses that surfaced it.
    sqli = merged[0]
    assert set(sqli.lenses) == {"auth-bypass", "deserialization"}


def test_dedupe_is_deterministic() -> None:
    passes = [
        [Hypothesis("H1", "SSRF via req.query.url", evidence="taint:2")],
        [Hypothesis("H1", "SSRF through request url", evidence="taint:2")],
    ]
    assert [h.title for h in dedupe_hypotheses(passes)] == [h.title for h in dedupe_hypotheses(passes)]


def test_dedupe_does_not_merge_distinct_leads() -> None:
    passes = [
        [Hypothesis("H1", "SQL injection at db.py", evidence="taint:1")],
        [Hypothesis("H1", "Open redirect in login handler", evidence="surface:8")],
    ]
    assert len(dedupe_hypotheses(passes)) == 2


def test_dedupe_keeps_same_class_at_different_endpoints_separate() -> None:
    """Similar titles at DIFFERENT endpoints (disjoint evidence) must not merge
    — otherwise a skeptic could confirm one using the other's evidence (#147b)."""
    passes = [
        [Hypothesis("H1", "Missing ownership check on GET /orders/{id}", evidence="surface:3")],
        [Hypothesis("H1", "Missing ownership check on GET /users/{id}", evidence="surface:7")],
    ]
    merged = dedupe_hypotheses(passes)
    assert len(merged) == 2


def test_multilens_generation_fans_out_and_dedupes() -> None:
    # Both lenses surface the same missing-ownership lead (near-identical
    # phrasing + shared evidence) plus one unique lead each.
    gen_by_lens = {
        "auth-bypass": "=== HYPOTHESES ===\nH1: Missing ownership check on GET /orders/{id} [evidence: surface:3, taint:1]\nH2: Unauthenticated POST /admin/reset [evidence: surface:5]\n",
        "business-logic-idor": "=== HYPOTHESES ===\nH1: Missing ownership check on GET /orders/{id} [evidence: surface:3]\nH2: Price manipulation in checkout [evidence: surface:9]\n",
    }
    lenses_seen = []

    def llm_call(mode, hypotheses=None, lens=None):
        if mode == "hunt_generate":
            lenses_seen.append(lens)
            return _result(gen_by_lens[lens])
        return _result("VERDICT H1: REFUTED — x\nVERDICT H2: REFUTED — x\nVERDICT H3: REFUTED — x")

    res = run_majority_verify(
        None, [], [], [], votes=1, llm_call=llm_call, lenses=["auth-bypass", "business-logic-idor"]
    )
    assert lenses_seen == ["auth-bypass", "business-logic-idor"]  # one generation pass per lens
    # SQLi restatement merged → 3 unique (SQLi, missing-auth, TOCTOU) > 2 per single pass.
    assert res.hypothesis_count == 3


# --- loop-until-dry / critic / budget (#147c) ------------------------------


def _gen(md, out=5):
    return LlmReviewResult(markdown=md, model="m", stop_reason=None,
                           usage={"output_tokens": out}, backend="api")


def _rounds_llm_call(round_markdowns, *, capture=None):
    """Build an llm_call that returns successive generation rounds, canned
    critic + refuting skeptic passes, optionally recording call kwargs."""
    state = {"n": 0}

    def llm_call(mode, hypotheses=None, lens=None, avoid_titles=None, critic_hint=None):
        if capture is not None:
            capture.append({"mode": mode, "avoid_titles": avoid_titles, "critic_hint": critic_hint})
        if mode == "hunt_generate":
            md = round_markdowns[min(state["n"], len(round_markdowns) - 1)]
            state["n"] += 1
            return _gen(md)
        if mode == "hunt_critic":
            return _gen("- try TOCTOU on balance update\n- check deserialization sinks")
        return _gen("VERDICT H1: REFUTED — x\nVERDICT H2: REFUTED — x\nVERDICT H3: REFUTED — x")

    return llm_call


def test_loop_stops_when_a_round_finds_nothing_new() -> None:
    rounds = [
        "=== HYPOTHESES ===\nH1: SQLi at db.py [evidence: taint:1]\n",
        "=== HYPOTHESES ===\nH1: SSRF via req.query.url [evidence: taint:3]\n",  # new
        "=== HYPOTHESES ===\nH1: SQLi at db.py [evidence: taint:1]\n",  # restatement → dry
    ]
    cap: list[dict] = []
    res = run_majority_verify(
        None, [], [], [], votes=1, llm_call=_rounds_llm_call(rounds, capture=cap),
        max_rounds=9, dry_streak=1,
    )
    assert res.rounds == 3  # stopped at the dry round, not all 9
    assert res.hypothesis_count == 2
    gen_calls = [c for c in cap if c["mode"] == "hunt_generate"]
    assert len(gen_calls) == 3


def test_loop_respects_max_rounds_cap() -> None:
    # Every round yields a fresh lead, so only the cap stops it.
    rounds = [f"=== HYPOTHESES ===\nH1: distinct issue in module_{i}_widget [evidence: taint:{i}]\n" for i in range(10)]
    res = run_majority_verify(
        None, [], [], [], votes=1, llm_call=_rounds_llm_call(rounds), max_rounds=3, dry_streak=1,
    )
    assert res.rounds == 3
    assert res.hypothesis_count == 3


def test_loop_respects_token_budget() -> None:
    rounds = [f"=== HYPOTHESES ===\nH1: distinct issue in module_{i}_widget [evidence: taint:{i}]\n" for i in range(10)]
    # Each generation ~5 output tokens + critic ~5; a 12-token budget allows a
    # couple rounds, not all 10.
    res = run_majority_verify(
        None, [], [], [], votes=1, llm_call=_rounds_llm_call(rounds),
        max_rounds=10, dry_streak=1, token_budget=12,
    )
    assert res.rounds < 10
    assert res.usage["output_tokens"] >= 12  # stopped after crossing the budget


def test_critic_seeds_next_round_with_avoid_titles() -> None:
    rounds = [
        "=== HYPOTHESES ===\nH1: SQLi at db.py [evidence: taint:1]\n",
        "=== HYPOTHESES ===\nH1: TOCTOU on balance update [evidence: taint:2]\n",
    ]
    cap: list[dict] = []
    run_majority_verify(
        None, [], [], [], votes=1, llm_call=_rounds_llm_call(rounds, capture=cap),
        max_rounds=2, dry_streak=1,
    )
    # A critic pass ran between the two productive rounds.
    assert any(c["mode"] == "hunt_critic" for c in cap)
    # The 2nd generation round was told what to avoid + given the critic hint.
    gen2 = [c for c in cap if c["mode"] == "hunt_generate"][1]
    assert gen2["avoid_titles"] and any("SQLi" in t for t in gen2["avoid_titles"])
    assert gen2["critic_hint"] and "TOCTOU" in gen2["critic_hint"]


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


def test_cli_hunt_lenses_routes_through_harness(tmp_path: Path, monkeypatch) -> None:
    """`--hunt-lenses 2` engages the harness even at --verify-votes 1 (#147b)."""
    gen = "=== HYPOTHESES ===\nH1: eval of request arg [evidence: taint:1]\n"

    def fake(*args, **kwargs):
        if kwargs.get("mode") == "hunt_generate":
            return _result(gen)
        return _result("VERDICT H1: REFUTED — arg is constant")

    monkeypatch.setattr("attackmap.cli.generate_llm_review", fake)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["analyze", str(_repo(tmp_path)), "--output", str(out),
         "--hunt", "--verify", "--hunt-lenses", "2", "--verify-votes", "1"],
    )
    assert result.exit_code == 0, result.output
    meta = json.loads((out / "vulnerability-hypotheses.meta.json").read_text(encoding="utf-8"))
    assert len(meta["lenses"]) == 2


def test_cli_hunt_rounds_routes_through_harness(tmp_path: Path, monkeypatch) -> None:
    """`--hunt-rounds 2` engages the loop harness; meta records rounds_run."""
    rounds = [
        "=== HYPOTHESES ===\nH1: eval of request arg [evidence: taint:1]\n",
        "=== HYPOTHESES ===\nH1: eval of request arg [evidence: taint:1]\n",  # dry
    ]
    state = {"n": 0}

    def fake(*args, **kwargs):
        mode = kwargs.get("mode")
        if mode == "hunt_generate":
            md = rounds[min(state["n"], len(rounds) - 1)]
            state["n"] += 1
            return _result(md)
        if mode == "hunt_critic":
            return _result("- try races")
        return _result("VERDICT H1: REFUTED — constant")

    monkeypatch.setattr("attackmap.cli.generate_llm_review", fake)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["analyze", str(_repo(tmp_path)), "--output", str(out),
         "--hunt", "--verify", "--hunt-rounds", "2", "--verify-votes", "1"],
    )
    assert result.exit_code == 0, result.output
    meta = json.loads((out / "vulnerability-hypotheses.meta.json").read_text(encoding="utf-8"))
    assert meta["rounds_run"] >= 1


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
