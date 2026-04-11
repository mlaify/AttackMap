from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load_eval_fixture(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_review_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _extract_section(text: str, heading: str) -> str:
    pattern = re.compile(rf"^\s*##\s+{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        return ""
    start = match.end()
    next_heading = re.search(r"^\s*##\s+.+$", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(text)
    return text[start:end].strip()


def _extract_bullets(section_text: str) -> list[str]:
    return [line.strip()[2:].strip() for line in section_text.splitlines() if line.strip().startswith("- ")]


def _count_matches(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


def evaluate_review_text(review_text: str, fixture: dict[str, Any]) -> dict[str, Any]:
    expectations = fixture.get("expectations", {})
    checks: list[dict[str, Any]] = []

    grounding = expectations.get("grounding", {})
    citation_pattern = grounding.get("citation_pattern", r"(?:surface|finding|path):\d+")
    citations = sorted(set(re.findall(citation_pattern, review_text, flags=re.IGNORECASE)))
    allowed_ids = set(grounding.get("allowed_ids", []))
    unknown_citations = sorted(citation for citation in citations if citation not in allowed_ids) if allowed_ids else []
    min_citations = int(grounding.get("min_citations", 0))
    grounding_pass = len(citations) >= min_citations and not unknown_citations
    checks.append(
        {
            "name": "grounding",
            "passed": grounding_pass,
            "details": {
                "citations_found": citations,
                "unknown_citations": unknown_citations,
                "min_citations_required": min_citations,
            },
        }
    )

    observed_inferred = expectations.get("observed_inferred", {})
    observed_token = observed_inferred.get("observed_token", r"\bOBSERVED\b")
    inferred_token = observed_inferred.get("inferred_token", r"\bINFERRED\b")
    observed_count = _count_matches(review_text, observed_token)
    inferred_count = _count_matches(review_text, inferred_token)
    observed_required = int(observed_inferred.get("min_observed", 0))
    inferred_required = int(observed_inferred.get("min_inferred", 0))
    oi_pass = observed_count >= observed_required and inferred_count >= inferred_required
    checks.append(
        {
            "name": "observed_vs_inferred_discipline",
            "passed": oi_pass,
            "details": {
                "observed_count": observed_count,
                "inferred_count": inferred_count,
                "min_observed_required": observed_required,
                "min_inferred_required": inferred_required,
            },
        }
    )

    strengths_expectation = expectations.get("strengths", {})
    strengths_section = _extract_section(review_text, "Strengths")
    strengths_items = _extract_bullets(strengths_section)
    strengths_keywords = [keyword.lower() for keyword in strengths_expectation.get("required_keywords", [])]
    strengths_text = strengths_section.lower()
    missing_strengths_keywords = [keyword for keyword in strengths_keywords if keyword not in strengths_text]
    min_strengths_items = int(strengths_expectation.get("min_items", 0))
    strengths_pass = len(strengths_items) >= min_strengths_items and not missing_strengths_keywords
    checks.append(
        {
            "name": "strengths_coverage",
            "passed": strengths_pass,
            "details": {
                "item_count": len(strengths_items),
                "min_items_required": min_strengths_items,
                "missing_keywords": missing_strengths_keywords,
            },
        }
    )

    weakness_expectation = expectations.get("weaknesses_hotspots", {})
    weakness_section = _extract_section(review_text, "Weaknesses / Risk Hotspots")
    weakness_items = _extract_bullets(weakness_section)
    min_weakness_items = int(weakness_expectation.get("min_items", 0))
    weakness_terms = [term.lower() for term in weakness_expectation.get("required_terms", [])]
    weakness_text = weakness_section.lower()
    missing_weakness_terms = [term for term in weakness_terms if term not in weakness_text]
    weakness_pass = len(weakness_items) >= min_weakness_items and not missing_weakness_terms
    checks.append(
        {
            "name": "weakness_hotspot_quality",
            "passed": weakness_pass,
            "details": {
                "item_count": len(weakness_items),
                "min_items_required": min_weakness_items,
                "missing_terms": missing_weakness_terms,
            },
        }
    )

    recommendation_expectation = expectations.get("recommendations", {})
    recommendation_section = _extract_section(review_text, "Prioritized Recommendations")
    recommendation_items = _extract_bullets(recommendation_section)
    min_recommendation_items = int(recommendation_expectation.get("min_items", 0))
    action_verbs = [verb.lower() for verb in recommendation_expectation.get("action_verbs", [])]
    recommendation_text = recommendation_section.lower()
    recommendation_verbs_present = [verb for verb in action_verbs if verb in recommendation_text]
    recommendation_pass = len(recommendation_items) >= min_recommendation_items and bool(recommendation_verbs_present)
    checks.append(
        {
            "name": "recommendation_usefulness",
            "passed": recommendation_pass,
            "details": {
                "item_count": len(recommendation_items),
                "min_items_required": min_recommendation_items,
                "action_verbs_present": recommendation_verbs_present,
            },
        }
    )

    false_positive_expectation = expectations.get("false_positive_control", {})
    banned_phrases = [phrase.lower() for phrase in false_positive_expectation.get("banned_phrases", [])]
    lowered_review = review_text.lower()
    found_banned = [phrase for phrase in banned_phrases if phrase in lowered_review]
    required_cautions = [phrase.lower() for phrase in false_positive_expectation.get("required_cautions", [])]
    missing_cautions = [phrase for phrase in required_cautions if phrase not in lowered_review]
    false_positive_pass = not found_banned and not missing_cautions
    checks.append(
        {
            "name": "false_positive_control",
            "passed": false_positive_pass,
            "details": {
                "found_banned_phrases": found_banned,
                "missing_required_cautions": missing_cautions,
            },
        }
    )

    passed_count = sum(1 for check in checks if check["passed"])
    total_count = len(checks)
    score = round((passed_count / total_count) * 100.0, 2) if total_count else 0.0
    return {
        "fixture_id": fixture.get("fixture_id", "unknown"),
        "target": fixture.get("target", {}),
        "summary": {
            "score": score,
            "passed_checks": passed_count,
            "total_checks": total_count,
            "status": "pass" if passed_count == total_count else "fail",
        },
        "checks": checks,
    }


def run_evaluation(fixture_path: str | Path, review_path: str | Path) -> dict[str, Any]:
    fixture = load_eval_fixture(fixture_path)
    review_text = load_review_text(review_path)
    return evaluate_review_text(review_text, fixture)


def _resolve_review_path_for_fixture(fixture_path: Path, fixture: dict[str, Any], reviews_dir: Path) -> Path:
    configured = fixture.get("review_file")
    if isinstance(configured, str) and configured.strip():
        return (reviews_dir / configured).resolve()
    return (reviews_dir / f"{fixture_path.stem}.md").resolve()


def run_evaluation_suite(fixtures_dir: str | Path, reviews_dir: str | Path) -> dict[str, Any]:
    fixture_dir_path = Path(fixtures_dir).resolve()
    review_dir_path = Path(reviews_dir).resolve()
    fixture_paths = sorted(fixture_dir_path.glob("*.json"))
    cases: list[dict[str, Any]] = []

    for fixture_path in fixture_paths:
        fixture = load_eval_fixture(fixture_path)
        review_path = _resolve_review_path_for_fixture(fixture_path, fixture, review_dir_path)
        if not review_path.exists():
            cases.append(
                {
                    "fixture_id": fixture.get("fixture_id", fixture_path.stem),
                    "summary": {
                        "score": 0.0,
                        "passed_checks": 0,
                        "total_checks": 1,
                        "status": "fail",
                    },
                    "checks": [
                        {
                            "name": "review_file_presence",
                            "passed": False,
                            "details": {"missing_review_path": str(review_path)},
                        }
                    ],
                }
            )
            continue
        cases.append(run_evaluation(fixture_path, review_path))

    passed = sum(1 for case in cases if case["summary"]["status"] == "pass")
    total = len(cases)
    avg_score = round(sum(case["summary"]["score"] for case in cases) / total, 2) if total else 0.0
    return {
        "suite": {
            "fixtures_dir": str(fixture_dir_path),
            "reviews_dir": str(review_dir_path),
            "fixture_count": total,
            "passed": passed,
            "failed": total - passed,
            "average_score": avg_score,
            "status": "pass" if total > 0 and passed == total else "fail",
        },
        "cases": cases,
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AttackMap defensive review output against a fixture spec.")
    parser.add_argument("--fixture", help="Path to evaluation fixture JSON.")
    parser.add_argument("--review", help="Path to review markdown output to evaluate.")
    parser.add_argument("--fixtures-dir", help="Directory containing evaluation fixture JSON files.")
    parser.add_argument("--reviews-dir", help="Directory containing review markdown outputs for suite mode.")
    parser.add_argument("--json", action="store_true", help="Print full JSON result.")
    args = parser.parse_args()

    if args.fixtures_dir or args.reviews_dir:
        if not (args.fixtures_dir and args.reviews_dir):
            parser.error("--fixtures-dir and --reviews-dir must be used together.")
        if args.fixture or args.review:
            parser.error("Use either single mode (--fixture/--review) or suite mode (--fixtures-dir/--reviews-dir), not both.")
        suite_result = run_evaluation_suite(args.fixtures_dir, args.reviews_dir)
        if args.json:
            print(json.dumps(suite_result, indent=2))
        else:
            summary = suite_result["suite"]
            print(f"Suite fixtures: {summary['fixture_count']}")
            print(f"Pass: {summary['passed']}, Fail: {summary['failed']}, Average score: {summary['average_score']}")
            print(f"Status: {summary['status']}")
            for case in suite_result["cases"]:
                case_summary = case["summary"]
                print(f"- {case['fixture_id']}: {case_summary['status']} ({case_summary['score']})")
        return 0 if suite_result["suite"]["status"] == "pass" else 1

    if not (args.fixture and args.review):
        parser.error("Single mode requires --fixture and --review.")

    result = run_evaluation(args.fixture, args.review)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        summary = result["summary"]
        print(f"Fixture: {result['fixture_id']}")
        print(f"Score: {summary['score']} ({summary['passed_checks']}/{summary['total_checks']} checks)")
        print(f"Status: {summary['status']}")
        for check in result["checks"]:
            mark = "PASS" if check["passed"] else "FAIL"
            print(f"- {mark}: {check['name']}")
    return 0 if result["summary"]["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
