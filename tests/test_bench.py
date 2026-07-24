import json
from pathlib import Path

from attackmap.bench import (
    Benchmark,
    Case,
    Expected,
    aggregate,
    bench_json,
    canonical_category,
    load_benchmark,
    min_scored_metric,
    render_markdown,
    run_benchmark,
    score_case,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _finding(title, tags, evidence):
    return {"title": title, "tags": tags, "evidence": evidence}


# --- category mapping --------------------------------------------------------


def test_canonical_category_maps_precise_classes():
    assert canonical_category(_finding(
        "State-changing routes are reachable without an authentication control",
        ["exposed-endpoint", "auth-missing", "state-changing"], [])) == "unauth_state_change"
    assert canonical_category(_finding(
        "Public webhook endpoint may trust attacker-controlled events",
        ["exposed-endpoint", "auth-missing"], [])) == "webhook_exposure"
    assert canonical_category(_finding(
        "Possible broken object-level authorization (BOLA/IDOR) on read routes",
        ["broken-authorization"], [])) == "bola"
    assert canonical_category(_finding(
        "Potential SQL injection via request body", ["injection"], [])) == "injection"


def test_canonical_category_advisory_is_unscored():
    assert canonical_category(_finding(
        "Secret-bearing environment variables are referenced", ["secret-exposure"], [])) == "secret_env"
    assert canonical_category(_finding(
        "Administrative routes appear reachable", ["privileged"], [])) == "admin_exposure"
    assert canonical_category(_finding(
        "Public routes likely sit close to sensitive data", ["exposed-endpoint", "data-risk"], [])) == "advisory"


# --- scoring -----------------------------------------------------------------


def test_true_positive_matches_by_route_and_file():
    findings = [_finding(
        "State-changing routes are reachable without an authentication control",
        ["auth-missing", "state-changing"],
        ["POST /orders in app.py:14 — no authentication control found"])]
    expected = [Expected(category="unauth_state_change", route="/orders", method="POST", file="app.py", line=14)]
    scores = score_case(findings, expected, ["unauth_state_change"], window=8)
    cs = scores["unauth_state_change"]
    assert cs.tp == 1 and cs.fp == 0
    assert cs.precision == 1.0 and cs.recall == 1.0


def test_recall_gap_when_no_finding_matches():
    # An injection ground-truth label with no injection finding → recall 0, no FP.
    expected = [Expected(category="injection", route="/orders", method="POST", file="app.py", line=24)]
    scores = score_case([], expected, ["injection"], window=8)
    cs = scores["injection"]
    assert cs.recall == 0.0
    assert cs.precision is None  # no findings → precision undefined
    assert cs.missed_expected


def test_false_positive_counts_against_precision():
    # A scored-category finding that matches no label is an FP.
    findings = [_finding(
        "Potential SQL injection", ["injection"],
        ["GET /elsewhere in other.py:99"])]
    expected = [Expected(category="injection", route="/orders", method="POST", file="app.py", line=24)]
    scores = score_case(findings, expected, ["injection"], window=8)
    cs = scores["injection"]
    assert cs.fp == 1
    assert cs.precision == 0.0
    assert cs.recall == 0.0


def test_advisory_findings_never_score_as_false_positives():
    findings = [
        _finding("Secret-bearing environment variables are referenced", ["secret-exposure"],
                 ["KEY in app.py:5"]),
        _finding("Public routes likely sit close to sensitive data", ["exposed-endpoint", "data-risk"],
                 ["app.py:1"]),
    ]
    expected = [Expected(category="unauth_state_change", route="/x", method="POST", file="app.py", line=1)]
    scores = score_case(findings, expected, ["unauth_state_change"], window=8)
    # No scored findings → the unauth label is simply a recall miss, no FP inflation.
    cs = scores["unauth_state_change"]
    assert cs.fp == 0
    assert cs.recall == 0.0


def test_grouped_finding_matches_multiple_expected():
    # One finding that cites two true routes helps recall twice, precision once.
    findings = [_finding(
        "State-changing routes are reachable without an authentication control",
        ["auth-missing", "state-changing"],
        ["POST /a in app.py:10 — no control", "POST /b in app.py:20 — no control"])]
    expected = [
        Expected(category="unauth_state_change", route="/a", method="POST", file="app.py", line=10),
        Expected(category="unauth_state_change", route="/b", method="POST", file="app.py", line=20),
    ]
    scores = score_case(findings, expected, ["unauth_state_change"], window=8)
    cs = scores["unauth_state_change"]
    assert cs.recall == 1.0            # both labels matched
    assert cs.tp == 1 and cs.fp == 0   # single finding, matched → one TP
    assert cs.precision == 1.0


# --- harness plumbing --------------------------------------------------------


def test_route_substring_does_not_credit_a_different_endpoint():
    # Codex P1: a finding about /orders/search must NOT match a /orders label.
    finding = _finding("Potential SQL injection", ["injection"],
                       ["GET /orders/search in app.py:40 — concatenated query"])
    exp = Expected(category="injection", route="/orders", method="POST", file="app.py", line=24)
    scores = score_case([finding], [exp], ["injection"], window=8)
    cs = scores["injection"]
    assert cs.recall == 0.0        # /orders label unmatched
    assert cs.fp == 1              # the /orders/search finding is a genuine non-match here


def test_method_mismatch_is_not_a_match():
    finding = _finding("State-changing routes reachable without auth",
                       ["auth-missing", "state-changing"], ["GET /orders in app.py:14"])
    exp = Expected(category="unauth_state_change", route="/orders", method="POST", file="app.py", line=14)
    scores = score_case([finding], [exp], ["unauth_state_change"], window=8)
    assert scores["unauth_state_change"].recall == 0.0


def test_repo_relative_path_prevents_cross_file_collision():
    # Codex P1: services/a/app.py finding must not match a services/b/app.py label.
    finding = _finding("SQL injection", ["injection"],
                       ["POST /x in services/a/app.py:10"])
    exp = Expected(category="injection", route="/x", method="POST", file="services/b/app.py", line=10)
    scores = score_case([finding], [exp], ["injection"], window=8)
    assert scores["injection"].recall == 0.0
    assert scores["injection"].fp == 1  # finding cites a file no label owns


def test_line_fallback_only_when_finding_has_no_route():
    # A routeless injection finding (sink cite only) matches by line window.
    finding = _finding("SQL injection sink", ["injection"], ["unsanitized SQL at app.py:41"])
    exp = Expected(category="injection", route="/orders/search", method="GET", file="app.py", line=40)
    scores = score_case([finding], [exp], ["injection"], window=8)
    assert scores["injection"].recall == 1.0


def test_f1_is_zero_not_none_when_precision_or_recall_zero():
    # Codex P2: 1 FP + 1 miss → precision 0, recall 0, F1 defined as 0.0.
    from attackmap.bench import CategoryScore
    cs = CategoryScore(category="injection", tp=0, fp=1,
                       matched_expected=[], missed_expected=["x"])
    assert cs.precision == 0.0 and cs.recall == 0.0
    assert cs.f1 == 0.0
    # Truly undefined (no findings, no labels) stays None.
    empty = CategoryScore(category="c")
    assert empty.f1 is None


def test_missing_case_directory_is_an_error_not_a_clean_pass():
    # Codex P2: an absent case path must not scan as a perfect clean repo.
    bm = Benchmark(scored_categories=("injection",), line_window=8,
                   cases=[Case(id="ghost", path="does/not/exist", expected=[])])
    calls = []
    results = run_benchmark(bm, ".", analyze=lambda p: calls.append(p) or [])
    assert results[0].error and "not found" in results[0].error
    assert not calls, "analyzer must not run on a missing case path"


def test_run_benchmark_with_injected_analyzer_and_aggregate():
    bm = Benchmark(
        scored_categories=("unauth_state_change",),
        line_window=8,
        cases=[Case(id="c1", path=".", expected=[
            Expected(category="unauth_state_change", route="/x", method="POST", file="app.py", line=3)])],
    )

    def fake_analyze(path):
        return [_finding("State-changing routes are reachable without an authentication control",
                         ["auth-missing", "state-changing"], ["POST /x in app.py:3 — no control"])]

    results = run_benchmark(bm, ".", analyze=fake_analyze)
    assert len(results) == 1 and results[0].error is None
    overall = aggregate(results)
    assert overall["unauth_state_change"].recall == 1.0
    payload = bench_json(results)
    assert payload["overall"]["unauth_state_change"]["tp"] == 1
    assert "c1" in [c["id"] for c in payload["cases"]]


def test_scan_failure_is_recorded_not_raised():
    bm = Benchmark(scored_categories=("injection",), line_window=8,
                   cases=[Case(id="boom", path=".", expected=[])])

    def boom(path):
        raise RuntimeError("scan exploded")

    results = run_benchmark(bm, ".", analyze=boom)
    assert results[0].error and "exploded" in results[0].error
    assert "ERROR" in render_markdown(results)


def test_min_scored_metric():
    bm = Benchmark(scored_categories=("unauth_state_change",), line_window=4,
                   cases=[Case(id="c", path=".", expected=[
                       Expected(category="unauth_state_change", route="/a", method="POST", file="app.py", line=1),
                       Expected(category="unauth_state_change", route="/b", method="POST", file="app.py", line=40)])])

    def one_of_two(path):
        # Cites only /a — /b is far away and its route string is absent → recall 0.5.
        return [_finding("State-changing routes are reachable without an authentication control",
                         ["auth-missing", "state-changing"], ["POST /a in app.py:1 — no control"])]

    results = run_benchmark(bm, ".", analyze=one_of_two)
    # precision 1.0, recall 0.5 → min is 0.5
    assert min_scored_metric(results) == 0.5


# --- shipped corpus ----------------------------------------------------------


def test_shipped_benchmark_manifest_is_valid_and_scores():
    manifest = REPO_ROOT / "evals" / "benchmark" / "benchmark.json"
    bm = load_benchmark(manifest)
    assert bm.cases, "benchmark should define cases"
    # Every expected label uses a category the manifest declares as scored.
    for case in bm.cases:
        for exp in case.expected:
            assert exp.category in bm.scored_categories, f"{case.id}: {exp.category} not scored"
    # Runs end-to-end against the real example apps; precision must be perfect
    # (no false positives) on the curated corpus — that is the standing invariant.
    results = run_benchmark(bm, REPO_ROOT)
    assert all(r.error is None for r in results)
    for cs in aggregate(results).values():
        if cs.precision is not None:
            assert cs.precision == 1.0, f"{cs.category} precision regressed: {cs.false_positives}"
