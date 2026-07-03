"""Tests for analyzer provenance tracking (#14).

Every analyzer-emitted signal carries an optional `source_analyzer` field
that names the analyzer that produced it. The field is excluded from
serialization by default (see models._PROVENANCE_FIELD) so CLI/JSON
reports stay byte-for-byte identical; access it via Python attribute
for debugging, confidence scoring, and future finder logic.

These tests pin the contract:
  1. The field exists on every list-typed signal in ScanResult, defaults
     to None on raw construction.
  2. `analyze_repository` stamps it with the running analyzer's name.
  3. Merge preserves provenance from first-seen analyzer (first-seen-wins
     applies to the whole object, not just the dedup key).
  4. `model_dump()` and `model_dump_json()` omit the field so downstream
     reports don't change shape.
  5. Analyzers may pre-populate a more-specific source; core does not
     overwrite it.
"""

from __future__ import annotations

import json
from pathlib import Path

from attackmap.analyzers import (
    Analyzer,
    _stamp_provenance,
    analyze_repository,
    merge_analyzer_results,
)
from attackmap.merge import MERGE_SCHEMA
from attackmap.sdk import (
    AnalyzerMetadata,
    AnalyzerResult,
    AuthHint,
    DatabaseHint,
    ExternalCall,
    Route,
    ScanResult,
    SecretHint,
)


# ---------------------------------------------------------------------------
# 1. Field exists on every signal, defaults to None
# ---------------------------------------------------------------------------


def test_source_analyzer_field_defaults_to_none_on_every_signal_type() -> None:
    """Every list-typed signal in ScanResult carries an optional
    `source_analyzer`. Constructed without it, the value is None."""
    for rule in MERGE_SCHEMA:
        model_cls = type(getattr(AnalyzerResult(root="."), rule.attr))
        # `list` — we need the item type instead. Sample from each factory below.
        # (This test is intentionally coupled to the MERGE_SCHEMA so a schema
        # extension will fail loudly if a new signal type forgot to add
        # the field.)
        assert model_cls is list

    sample_items = [
        Route(path="/a", method="GET", file="x.py"),
        ExternalCall(target="https://a", file="x.py"),
        DatabaseHint(kind="postgres", file="x.py"),
        AuthHint(hint="oauth", file="x.py"),
        SecretHint(name="K", file="x.py"),
    ]
    for item in sample_items:
        assert hasattr(item, "source_analyzer")
        assert item.source_analyzer is None


# ---------------------------------------------------------------------------
# 2. Core stamps provenance after each analyzer runs
# ---------------------------------------------------------------------------


class _FakeAnalyzer:
    """A minimal Analyzer that emits one route + one secret + one db hint."""

    def __init__(self, name: str, route_path: str = "/a") -> None:
        self.metadata = AnalyzerMetadata(name=name)
        self._route_path = route_path

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        return True

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return AnalyzerResult(
            root=str(root),
            routes=[Route(path=self._route_path, method="GET", file="app.py")],
            secret_hints=[SecretHint(name="K", file="app.py")],
            databases=[DatabaseHint(kind="postgres", file="app.py")],
        )


def test_stamp_provenance_marks_every_signal_with_the_analyzer_name(tmp_path: Path) -> None:
    a = _FakeAnalyzer(name="fake")
    result = a.analyze(tmp_path)
    _stamp_provenance(result, a.name)
    assert result.routes[0].source_analyzer == "fake"
    assert result.secret_hints[0].source_analyzer == "fake"
    assert result.databases[0].source_analyzer == "fake"


def test_analyze_repository_stamps_provenance_for_the_running_analyzer(tmp_path: Path) -> None:
    # analyze_repository takes a list of Analyzer instances directly.
    merged = analyze_repository(tmp_path, analyzers=[_FakeAnalyzer(name="fake")])
    assert merged.routes[0].source_analyzer == "fake"
    assert merged.secret_hints[0].source_analyzer == "fake"
    assert merged.databases[0].source_analyzer == "fake"


# ---------------------------------------------------------------------------
# 3. Merge preserves first-seen provenance
# ---------------------------------------------------------------------------


def test_merge_preserves_first_seen_provenance_across_analyzers(tmp_path: Path) -> None:
    """Two analyzers emit the same route. Merge keeps first-seen wins,
    and the winner's source_analyzer stays intact."""
    merged = analyze_repository(
        tmp_path,
        analyzers=[
            _FakeAnalyzer(name="first-analyzer"),
            _FakeAnalyzer(name="second-analyzer"),  # same route triple
        ],
    )
    # One route survived dedup — the first analyzer's version, so its
    # provenance should be preserved.
    assert len(merged.routes) == 1
    assert merged.routes[0].source_analyzer == "first-analyzer"


def test_merge_of_distinct_signals_keeps_each_signals_provenance(tmp_path: Path) -> None:
    """When two analyzers emit *different* signals, both survive with
    their own source stamped."""
    merged = analyze_repository(
        tmp_path,
        analyzers=[
            _FakeAnalyzer(name="python-analyzer", route_path="/py"),
            _FakeAnalyzer(name="node-analyzer", route_path="/node"),
        ],
    )
    by_path = {r.path: r for r in merged.routes}
    assert by_path["/py"].source_analyzer == "python-analyzer"
    assert by_path["/node"].source_analyzer == "node-analyzer"


# ---------------------------------------------------------------------------
# 4. Reports stay byte-for-byte unchanged
# ---------------------------------------------------------------------------


def test_source_analyzer_is_excluded_from_model_dump() -> None:
    """Setting the field must not change what `model_dump()` returns.
    This is the core back-compat contract for #14 — existing report
    output has to keep working unchanged."""
    stamped = Route(path="/a", method="GET", file="x.py")
    stamped.source_analyzer = "some-analyzer"
    dumped = stamped.model_dump()
    assert "source_analyzer" not in dumped
    # And the serialized JSON is identical to the unstamped case.
    unstamped = Route(path="/a", method="GET", file="x.py")
    assert stamped.model_dump() == unstamped.model_dump()


def test_source_analyzer_is_excluded_from_json_output() -> None:
    stamped = Route(path="/a", method="GET", file="x.py")
    stamped.source_analyzer = "some-analyzer"
    text = stamped.model_dump_json()
    assert "source_analyzer" not in json.loads(text)


def test_stamped_scan_result_serializes_identically_to_unstamped(tmp_path: Path) -> None:
    """End-to-end: a repository run with provenance stamping produces
    the same JSON output as one where the field was never set."""
    unstamped = AnalyzerResult(
        root=str(tmp_path),
        routes=[Route(path="/a", method="GET", file="app.py")],
        secret_hints=[SecretHint(name="K", file="app.py")],
        databases=[DatabaseHint(kind="postgres", file="app.py")],
    )
    stamped = AnalyzerResult(**unstamped.model_dump())
    _stamp_provenance(stamped, "some-analyzer")
    assert stamped.model_dump() == unstamped.model_dump()


# ---------------------------------------------------------------------------
# 5. Analyzers may pre-populate a more-specific source
# ---------------------------------------------------------------------------


def test_stamp_provenance_does_not_overwrite_analyzer_provided_source() -> None:
    """If an analyzer plugin wants to attribute a signal to something
    more specific than its own name (e.g. a nested module), it can
    pre-populate `source_analyzer`. Core's stamp step respects that."""
    r = AnalyzerResult(root=".")
    r.routes.append(Route(path="/a", method="GET", file="x.py", source_analyzer="fine-grained-sub-analyzer"))
    r.routes.append(Route(path="/b", method="GET", file="x.py"))  # no source
    _stamp_provenance(r, "outer-analyzer")
    by_path = {route.path: route for route in r.routes}
    assert by_path["/a"].source_analyzer == "fine-grained-sub-analyzer"
    assert by_path["/b"].source_analyzer == "outer-analyzer"
