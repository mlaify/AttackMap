from pathlib import Path

import json

from attackmap.review_eval import evaluate_review_text, load_eval_fixture, run_evaluation, run_evaluation_suite


def _fixture_path() -> Path:
    return Path("evals/fixtures/bluesky-atproto-review-v1.json")


def _good_review_path() -> Path:
    return Path("evals/samples/bluesky-atproto-good-review.md")


def _bad_review_path() -> Path:
    return Path("evals/samples/bluesky-atproto-bad-review.md")


def test_review_eval_good_sample_passes_all_checks() -> None:
    result = run_evaluation(_fixture_path(), _good_review_path())

    assert result["summary"]["status"] == "pass"
    assert result["summary"]["passed_checks"] == result["summary"]["total_checks"]


def test_review_eval_bad_sample_fails_multiple_checks() -> None:
    fixture = load_eval_fixture(_fixture_path())
    bad_review = _bad_review_path().read_text(encoding="utf-8")
    result = evaluate_review_text(bad_review, fixture)

    assert result["summary"]["status"] == "fail"
    check_status = {check["name"]: check["passed"] for check in result["checks"]}
    assert check_status["grounding"] is False
    assert check_status["observed_vs_inferred_discipline"] is False
    assert check_status["false_positive_control"] is False


def test_review_eval_suite_reports_pass_and_fail_cases(tmp_path: Path) -> None:
    fixtures_dir = tmp_path / "fixtures"
    reviews_dir = tmp_path / "reviews"
    fixtures_dir.mkdir()
    reviews_dir.mkdir()

    good_fixture = load_eval_fixture(_fixture_path())
    good_fixture["review_file"] = "good.md"
    (fixtures_dir / "good.json").write_text(json.dumps(good_fixture), encoding="utf-8")
    (reviews_dir / "good.md").write_text(_good_review_path().read_text(encoding="utf-8"), encoding="utf-8")

    bad_fixture = load_eval_fixture(_fixture_path())
    bad_fixture["review_file"] = "missing.md"
    bad_fixture["fixture_id"] = "missing-review-case"
    (fixtures_dir / "missing.json").write_text(json.dumps(bad_fixture), encoding="utf-8")

    result = run_evaluation_suite(fixtures_dir, reviews_dir)

    assert result["suite"]["fixture_count"] == 2
    assert result["suite"]["passed"] == 1
    assert result["suite"]["failed"] == 1
    assert result["suite"]["status"] == "fail"


def test_review_eval_suite_passes_for_shipped_corpus_samples() -> None:
    result = run_evaluation_suite(Path("evals/fixtures"), Path("evals/samples"))

    assert result["suite"]["fixture_count"] >= 3
    assert result["suite"]["failed"] == 0
    assert result["suite"]["status"] == "pass"


# ---------------------------------------------------------------------------
# #44: v2 rubric accepts semantic equivalents that v1 rejected.
# ---------------------------------------------------------------------------


def _v2_fixture_path() -> Path:
    return Path("evals/fixtures/bluesky-atproto-review-v2.json")


def test_v2_rubric_accepts_review_using_synonym_language_where_v1_would_reject() -> None:
    """A review that uses DPoP/JWKS/PAR for signing and NSID for XRPC
    is what Claude actually produces on real repos — v1's flat
    required_keywords check rejects this, v2's keyword groups accept
    it. FINDINGS §3 fix."""
    synonym_review = """
# Synonym-only review

OBSERVED: The OAuth provider issues bound tokens using DPoP.
See asset:auth-oauth-provider.
OBSERVED: JWKS is exposed at `.well-known/jwks.json`.
See surface:jwks-endpoint.
OBSERVED: PAR is required before authorize.
See control:par-required.
INFERRED: microservice boundaries are the real trust seam here.
See insight:service-boundaries.
INFERRED: DPoP binding to the sender's key mitigates token replay.
See insight:token-binding.

## Strengths

- The OAuth provider enforces DPoP token binding, backed by a JWKS
  publication that microservice callers can pin against.
- Service boundaries between the PDS and the AppView are named and
  well-scoped.

## Weaknesses / Risk Hotspots

- Trust boundary between the entryway service and the OAuth provider
  isn't uniformly authenticated.
- Every NSID under `com.atproto.identity.*` is a lexicon-driven
  handler and needs per-nsid authz review.
- Entry point concentration in one router file is a hotspot for review.

## Prioritized Recommendations

- Verify DPoP claim validation on every protected NSID.
- Audit JWKS rotation cadence.
- Document the boundary crossings between services.

## Analyst Notes

INFERRED to be a scanner artifact: control-absence for encryption_at_rest
is a source-quality caveat here — that lives at the datastore layer,
not application code.
"""
    v1 = load_eval_fixture(_fixture_path())
    v2 = load_eval_fixture(_v2_fixture_path())

    v1_result = evaluate_review_text(synonym_review, v1)
    v2_result = evaluate_review_text(synonym_review, v2)

    v1_status = {c["name"]: c["passed"] for c in v1_result["checks"]}
    v2_status = {c["name"]: c["passed"] for c in v2_result["checks"]}

    # v1 rejects the synonym language across the three checks that FINDINGS §3
    # documented as vocabulary-mismatched: strengths, weaknesses, cautions.
    assert v1_status["strengths_coverage"] is False
    assert v1_status["weakness_hotspot_quality"] is False
    # Semantic-equivalent cautions ("source-quality caveat" instead of
    # "low-quality" / "heuristic") also fail on v1.
    assert v1_status["false_positive_control"] is False

    # v2 accepts each of them.
    assert v2_status["strengths_coverage"] is True
    assert v2_status["weakness_hotspot_quality"] is True
    assert v2_status["false_positive_control"] is True

    # v2 also grounds against evidence-pack IDs beyond surface/finding/path
    # (asset:, insight:, control:) that v1 would flag as unknown citations.
    assert v2_status["grounding"] is True


def test_v2_rubric_still_rejects_the_bad_shipped_sample() -> None:
    """v2 broadens acceptance of good reviews — it must not accidentally
    accept the deliberately-bad review."""
    bad_review = _bad_review_path().read_text(encoding="utf-8")
    v2 = load_eval_fixture(_v2_fixture_path())
    result = evaluate_review_text(bad_review, v2)
    assert result["summary"]["status"] == "fail"


def test_v1_rubric_is_marked_deprecated() -> None:
    fixture = load_eval_fixture(_fixture_path())
    assert fixture.get("deprecated") is True
    assert "v2" in fixture.get("deprecation_note", "")
