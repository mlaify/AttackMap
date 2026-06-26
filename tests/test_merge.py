"""Tests for the centralized merge schema.

The schema in `attackmap.merge.MERGE_SCHEMA` is the single source of truth
for how analyzer outputs are combined. These tests pin down the rules so
future refactors stay honest:

- Every ScanResult list field is covered exactly once.
- Each dedup key is the documented tuple.
- First-seen wins; order is preserved across analyzers.
- Empty inputs work; single inputs are passthrough.
"""

from __future__ import annotations

import pytest

from attackmap.analyzers import merge_analyzer_results
from attackmap.merge import MERGE_SCHEMA, MergeRule, initial_seen, merge_into
from attackmap.sdk import (
    AnalyzerResult,
    AuthHint,
    DatabaseHint,
    EdgeHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)


# ---------------------------------------------------------------------------
# Schema coverage
# ---------------------------------------------------------------------------


def test_merge_schema_covers_every_list_field_on_scan_result() -> None:
    """If a new list field is added to ScanResult, this test fails until
    the schema is updated. Prevents silent merge gaps."""
    list_fields = {
        name
        for name, field in ScanResult.model_fields.items()
        if str(field.annotation).startswith("list[") and name != "languages"
    }
    schema_fields = {rule.attr for rule in MERGE_SCHEMA}
    assert list_fields == schema_fields, (
        f"Schema drift: ScanResult lists not in MERGE_SCHEMA: "
        f"{list_fields - schema_fields}; in schema but not on ScanResult: "
        f"{schema_fields - list_fields}"
    )


def test_merge_schema_attrs_are_unique() -> None:
    attrs = [rule.attr for rule in MERGE_SCHEMA]
    assert len(attrs) == len(set(attrs))


# ---------------------------------------------------------------------------
# Per-field dedup keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "attr, signals, expected_keys",
    [
        (
            "routes",
            [
                Route(path="/a", method="GET", file="x.py"),
                Route(path="/a", method="POST", file="x.py"),  # method differs → kept
                Route(path="/a", method="GET", file="y.py"),  # file differs → kept
                Route(path="/a", method="GET", file="x.py"),  # duplicate → dropped
            ],
            [("/a", "GET", "x.py"), ("/a", "POST", "x.py"), ("/a", "GET", "y.py")],
        ),
        (
            "external_calls",
            [
                ExternalCall(target="https://a.example", file="x.py"),
                ExternalCall(target="https://a.example", file="x.py"),  # dup → dropped
                ExternalCall(target="https://b.example", file="x.py"),
                ExternalCall(target="https://a.example", file="y.py"),
            ],
            [("https://a.example", "x.py"), ("https://b.example", "x.py"), ("https://a.example", "y.py")],
        ),
        (
            "databases",
            [
                DatabaseHint(kind="postgres", file="db.py"),
                DatabaseHint(kind="postgres", file="db.py"),  # dup
                DatabaseHint(kind="redis", file="db.py"),
            ],
            [("postgres", "db.py"), ("redis", "db.py")],
        ),
        (
            "auth_hints",
            [
                AuthHint(hint="oauth", file="auth.py"),
                AuthHint(hint="oauth", file="auth.py"),  # dup
                AuthHint(hint="session", file="auth.py"),
            ],
            [("oauth", "auth.py"), ("session", "auth.py")],
        ),
        (
            "secret_hints",
            [
                SecretHint(name="API_KEY", file="config.py"),
                SecretHint(name="API_KEY", file="config.py"),  # dup
                SecretHint(name="DB_PASSWORD", file="config.py"),
            ],
            [("API_KEY", "config.py"), ("DB_PASSWORD", "config.py")],
        ),
    ],
)
def test_dedup_keys_match_documented_schema(attr: str, signals: list, expected_keys: list) -> None:
    rule = next(r for r in MERGE_SCHEMA if r.attr == attr)
    result = AnalyzerResult(root=".")
    merge_into(result, signals, rule, initial_seen(result, rule))
    actual = [rule.key(item) for item in getattr(result, attr)]
    assert actual == expected_keys


# ---------------------------------------------------------------------------
# Ordering and across-result behavior
# ---------------------------------------------------------------------------


def test_merge_preserves_first_seen_order_across_analyzers() -> None:
    first = AnalyzerResult(
        root=".",
        routes=[
            Route(path="/a", method="GET", file="x.py"),
            Route(path="/b", method="GET", file="x.py"),
        ],
    )
    second = AnalyzerResult(
        root=".",
        routes=[
            Route(path="/b", method="GET", file="x.py"),  # dup of first.b
            Route(path="/c", method="GET", file="x.py"),
        ],
    )
    merged = merge_analyzer_results([first, second], root=".")
    paths = [r.path for r in merged.routes]
    assert paths == ["/a", "/b", "/c"], "first-seen ordering broken"


def test_merge_with_no_results_returns_empty_scan_at_root() -> None:
    merged = merge_analyzer_results([], root="/tmp/some-repo")
    assert merged.routes == []
    assert merged.languages == []
    assert merged.files_scanned == 0
    assert merged.root.endswith("some-repo")


def test_merge_single_result_passes_through_unchanged() -> None:
    original = AnalyzerResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/a", method="GET", file="x.py")],
        secret_hints=[SecretHint(name="K", file="c.py")],
        files_scanned=1,
    )
    merged = merge_analyzer_results([original], root=".")
    assert merged.routes == original.routes
    assert merged.secret_hints == original.secret_hints
    assert merged.languages == ["python"]
    assert merged.files_scanned == 1


def test_languages_are_merged_and_sorted() -> None:
    first = AnalyzerResult(root=".", languages=["python", "javascript"])
    second = AnalyzerResult(root=".", languages=["python", "rust"])
    merged = merge_analyzer_results([first, second], root=".")
    assert merged.languages == ["javascript", "python", "rust"]


# ---------------------------------------------------------------------------
# MergeRule construction guards
# ---------------------------------------------------------------------------


def test_merge_rule_rejects_invalid_attr() -> None:
    with pytest.raises(ValueError):
        MergeRule("not an identifier", key=lambda x: (x,))
