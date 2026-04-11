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
