"""Tests for OSV CVE lookup (#60, slice 2 of #48)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.cve import (
    LookupSummary,
    map_severity,
    query_vulnerabilities,
    resolve_concrete_version,
)
from attackmap.models import DependencyHint, ScanResult, Vulnerability
from attackmap.threat_model import generate_findings


runner = CliRunner()


# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.0.0", "1.0.0"),
        ("v1.9.1", "1.9.1"),
        ("^4.16.0", "4.16.0"),
        ("~5.4.0", "5.4.0"),
        (">=2.28,<3", "2.28.0"),
        ("==21.2.0", "21.2.0"),
        (">=2.9", "2.9.0"),
        ("1.0", "1.0.0"),
        ("1", "1.0.0"),
    ],
)
def test_resolve_concrete_version_extracts_lower_bound(raw: str, expected: str) -> None:
    assert resolve_concrete_version(raw) == expected


@pytest.mark.parametrize("raw", ["*", "latest", "any", "N/A", "", "   "])
def test_resolve_concrete_version_returns_none_for_unpinned(raw: str) -> None:
    assert resolve_concrete_version(raw) is None


def test_resolve_concrete_version_preserves_prerelease() -> None:
    assert resolve_concrete_version("1.2.3-beta.1") == "1.2.3-beta.1"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def test_map_severity_prefers_numeric_cvss_score() -> None:
    entry = {"severity": [{"type": "CVSS_V3", "score": "8.5"}]}
    severity, score = map_severity(entry)
    assert severity == "high"
    assert score == 8.5


def test_map_severity_bucket_boundaries() -> None:
    assert map_severity({"severity": [{"type": "CVSS_V3", "score": "9.9"}]})[0] == "high"
    assert map_severity({"severity": [{"type": "CVSS_V3", "score": "7.0"}]})[0] == "high"
    assert map_severity({"severity": [{"type": "CVSS_V3", "score": "6.9"}]})[0] == "medium"
    assert map_severity({"severity": [{"type": "CVSS_V3", "score": "4.0"}]})[0] == "medium"
    assert map_severity({"severity": [{"type": "CVSS_V3", "score": "3.9"}]})[0] == "low"


def test_map_severity_falls_back_to_database_specific_label() -> None:
    entry = {"database_specific": {"severity": "HIGH"}}
    assert map_severity(entry)[0] == "high"
    entry = {"database_specific": {"severity": "MODERATE"}}
    assert map_severity(entry)[0] == "medium"
    entry = {"database_specific": {"severity": "LOW"}}
    assert map_severity(entry)[0] == "low"


def test_map_severity_defaults_to_medium_when_unknown() -> None:
    assert map_severity({})[0] == "medium"


def test_map_severity_ignores_cvss_vector_without_numeric_score() -> None:
    """Raw CVSS vectors like `CVSS:3.1/AV:N/...` don't carry a computed
    score; we don't vendor a CVSS calculator, so we fall back to the
    label — or medium if no label either."""
    entry = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N"}]}
    severity, score = map_severity(entry)
    assert severity == "medium"
    assert score is None


# ---------------------------------------------------------------------------
# Query behavior — cache, offline, dedup
# ---------------------------------------------------------------------------


def _osv_vuln(
    vid: str = "GHSA-test-1234",
    *,
    severity_score: str | None = "8.5",
    aliases: list[str] | None = None,
    summary: str = "Path traversal in the sample package.",
) -> dict:
    entry: dict = {
        "id": vid,
        "summary": summary,
        "aliases": aliases or ["CVE-2023-9999"],
        "references": [{"type": "ADVISORY", "url": "https://example.com/adv"}],
        "affected": [
            {
                "package": {"name": "sample-pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ],
    }
    if severity_score is not None:
        entry["severity"] = [{"type": "CVSS_V3", "score": severity_score}]
    return entry


def _stub_transport(responses_by_body_hint: dict[str, dict]):
    """Return a transport speaking the OSV batch + detail protocol.

    ``responses_by_body_hint`` keys are substrings matched against the
    queried package name; values are classic ``/v1/query``-shaped dicts
    (``{"vulns": [full entries]}``). The stub answers:

    - ``POST /v1/querybatch`` → per-query ID references derived from the
      matched canned payload,
    - ``GET /v1/vulns/{id}`` → the full canned entry for that ID,
    - ``POST /v1/query`` (pagination fallback) → the canned payload as-is.
    """
    calls: list[tuple[str, bytes]] = []

    def _match(text: str) -> dict | None:
        for hint, payload in responses_by_body_hint.items():
            if hint in text:
                return payload
        return None

    def transport(url: str, body: bytes) -> bytes:
        calls.append((url, body))
        if url.endswith("/v1/querybatch"):
            request = json.loads(body.decode("utf-8"))
            results = []
            for query in request["queries"]:
                payload = _match(query["package"]["name"])
                if payload and payload.get("vulns"):
                    results.append(
                        {"vulns": [{"id": v["id"], "modified": ""} for v in payload["vulns"]]}
                    )
                else:
                    results.append({})
            return json.dumps({"results": results}).encode("utf-8")
        if "/v1/vulns/" in url:
            vuln_id = url.rsplit("/", 1)[1]
            for payload in responses_by_body_hint.values():
                for entry in payload.get("vulns", []):
                    if entry["id"] == vuln_id:
                        return json.dumps(entry).encode("utf-8")
            return json.dumps({}).encode("utf-8")
        # Classic single query (the pagination fallback path).
        payload = _match(body.decode("utf-8"))
        return json.dumps(payload if payload else {"vulns": []}).encode("utf-8")

    return transport, calls


def _dep(name: str = "sample-pkg", version: str = "1.0.0", ecosystem: str = "pypi") -> DependencyHint:
    return DependencyHint(name=name, version=version, ecosystem=ecosystem, file="pyproject.toml")


def test_query_returns_vulnerabilities_from_stubbed_response(tmp_path: Path) -> None:
    transport, calls = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    vulns, summary = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=transport)
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-test-1234"
    assert vulns[0].severity == "high"
    assert vulns[0].package_name == "sample-pkg"
    assert vulns[0].package_version == "1.0.0"
    assert vulns[0].source_analyzer == "cve"
    assert summary.queried == 1


def test_query_dedups_repeated_vulns_across_deps(tmp_path: Path) -> None:
    """Two DependencyHints for the same (eco, name, version) dedupe to one
    unique package — queried once, surfaced once."""
    transport, calls = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    deps = [_dep(), _dep()]  # same fingerprint twice
    vulns, summary = query_vulnerabilities(deps, cache_dir=tmp_path, transport=transport)
    assert len(vulns) == 1
    assert summary.queried == 1
    assert summary.cached == 0


def test_query_skips_deps_without_queryable_version(tmp_path: Path) -> None:
    transport, calls = _stub_transport({})
    deps = [
        _dep(version="*"),
        _dep(version="latest"),
        _dep(version=""),
    ]
    vulns, summary = query_vulnerabilities(deps, cache_dir=tmp_path, transport=transport)
    assert vulns == []
    assert summary.skipped_no_version == 3
    assert not calls  # transport should never have been called


def test_query_uses_cache_on_second_call(tmp_path: Path) -> None:
    transport, calls = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    dep = _dep()
    vulns1, s1 = query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport)
    first_run_calls = len(calls)  # one batch POST + one detail GET
    vulns2, s2 = query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport)
    assert len(calls) == first_run_calls  # second run hit the cache — no network
    assert s1.queried == 1 and s2.cached == 1
    # Vulns from the cached run should mirror the network run.
    assert [v.id for v in vulns2] == [v.id for v in vulns1]


def test_query_ignores_stale_cache_beyond_ttl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    transport, calls = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    dep = _dep()
    # First call at t=0.
    query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport, clock=lambda: 0.0)
    first_run_calls = len(calls)
    assert first_run_calls > 0
    # Second call 25 hours later with default 24h TTL — cache invalidated,
    # so the network is hit again.
    monkeypatch.setenv("ATTACKMAP_OSV_CACHE_TTL_HOURS", "24")
    later = 25 * 3600.0
    query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport, clock=lambda: later)
    assert len(calls) > first_run_calls


def test_query_offline_transport_error_falls_back_gracefully(tmp_path: Path) -> None:
    """A transport that raises should not sink the run — the dep is
    counted as skipped_offline and the caller sees an empty list."""

    def failing_transport(url: str, body: bytes) -> bytes:
        raise OSError("no route to host")

    vulns, summary = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=failing_transport)
    assert vulns == []
    assert summary.skipped_offline == 1
    assert summary.network_errors == 1


def test_query_uses_warm_cache_when_transport_offline(tmp_path: Path) -> None:
    """Prime the cache with a network run, then run again with a broken
    transport — cache-served vulns should still surface."""
    transport, _ = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=transport, clock=lambda: 0.0)

    def failing_transport(url: str, body: bytes) -> bytes:
        raise OSError("no network")

    vulns, summary = query_vulnerabilities(
        [_dep()], cache_dir=tmp_path, transport=failing_transport, clock=lambda: 60.0
    )
    assert len(vulns) == 1
    assert summary.cached == 1
    assert summary.skipped_offline == 0


def test_query_ignores_unknown_ecosystem(tmp_path: Path) -> None:
    transport, calls = _stub_transport({"sample": {"vulns": [_osv_vuln()]}})
    # Pretend a rogue plugin emitted an ecosystem we don't map.
    dep = DependencyHint.model_construct(
        name="sample-pkg", version="1.0.0", ecosystem="ruby", file="Gemfile"
    )
    vulns, summary = query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport)
    assert vulns == []
    assert not calls


def test_query_extracts_affected_range_text(tmp_path: Path) -> None:
    transport, _ = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    vulns, _ = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=transport)
    assert vulns[0].affected_range == "affected: >= 0, fixed in 1.2.3"


def test_query_batches_many_packages_into_few_requests(tmp_path: Path) -> None:
    """The whole point of querybatch (#cve-batch): a big lockfile tree must
    not produce one HTTP request per package. 700 unique clean packages →
    2 batch POSTs (500 + 200) and zero detail fetches."""
    from attackmap.cve import _BATCH_SIZE, _OSV_BATCH_URL

    transport, calls = _stub_transport({})
    deps = [_dep(name=f"pkg-{i}") for i in range(_BATCH_SIZE + 200)]
    vulns, summary = query_vulnerabilities(deps, cache_dir=tmp_path, transport=transport)
    assert vulns == []
    assert summary.queried == _BATCH_SIZE + 200
    batch_calls = [c for c in calls if c[0] == _OSV_BATCH_URL]
    assert len(batch_calls) == 2
    assert len(calls) == 2  # no detail fetches for clean packages


def test_query_fetches_shared_vuln_details_once(tmp_path: Path) -> None:
    """Two packages hit by the same advisory ID → one /v1/vulns/{id} fetch
    (memoized per run), both packages still emit their Vulnerability."""
    from attackmap.cve import _OSV_VULNS_URL

    shared = _osv_vuln("GHSA-shared-1")
    transport, calls = _stub_transport({"pkg-a": {"vulns": [shared]}, "pkg-b": {"vulns": [shared]}})
    deps = [_dep(name="pkg-a"), _dep(name="pkg-b")]
    vulns, summary = query_vulnerabilities(deps, cache_dir=tmp_path, transport=transport)
    assert summary.queried == 2
    assert {v.package_name for v in vulns} == {"pkg-a", "pkg-b"}
    detail_calls = [c for c in calls if c[0].startswith(_OSV_VULNS_URL)]
    assert len(detail_calls) == 1


def test_query_failed_detail_fetch_is_not_cached(tmp_path: Path) -> None:
    """Codex P1: if the batch names an advisory but its /v1/vulns/{id} fetch
    fails, the package must NOT be cached — a cached partial/empty payload
    would suppress a known vulnerability for the whole TTL. The next run
    (connectivity restored) must query again and surface the vuln."""
    from attackmap.cve import _OSV_VULNS_URL

    good_transport, _ = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})

    def flaky_transport(url: str, body: bytes) -> bytes:
        if url.startswith(_OSV_VULNS_URL):
            raise OSError("transient network error")
        return good_transport(url, body)

    vulns1, s1 = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=flaky_transport)
    assert vulns1 == []
    assert s1.queried == 0
    assert s1.skipped_offline == 1

    # Connectivity restored: no stale cache entry may mask the advisory.
    vulns2, s2 = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=good_transport)
    assert [v.id for v in vulns2] == ["GHSA-test-1234"]
    assert s2.queried == 1
    assert s2.cached == 0


def test_query_fallback_follows_single_query_pagination(tmp_path: Path) -> None:
    """Codex P2: the single-query fallback must follow /v1/query's OWN
    next_page_token — the high-advisory packages that enter this branch
    paginate there too. All pages' vulns are merged; nothing is dropped."""
    from attackmap.cve import _OSV_BATCH_URL, _OSV_QUERY_URL

    page1 = {"vulns": [_osv_vuln("GHSA-page1-1")], "next_page_token": "page2"}
    page2 = {"vulns": [_osv_vuln("GHSA-page2-1")]}

    def transport(url: str, body: bytes) -> bytes:
        if url == _OSV_BATCH_URL:
            return json.dumps(
                {"results": [{"vulns": [{"id": "GHSA-page1-1", "modified": ""}], "next_page_token": "tok"}]}
            ).encode("utf-8")
        if url == _OSV_QUERY_URL:
            request = json.loads(body.decode("utf-8"))
            return json.dumps(page2 if request.get("page_token") == "page2" else page1).encode("utf-8")
        raise AssertionError(f"unexpected URL {url}")

    vulns, summary = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=transport)
    assert sorted(v.id for v in vulns) == ["GHSA-page1-1", "GHSA-page2-1"]
    assert summary.queried == 1

    # And the complete (both-pages) payload is what got cached.
    vulns_cached, s2 = query_vulnerabilities(
        [_dep()], cache_dir=tmp_path, transport=transport
    )
    assert sorted(v.id for v in vulns_cached) == ["GHSA-page1-1", "GHSA-page2-1"]
    assert s2.cached == 1


def test_query_paginated_batch_result_falls_back_to_single_query(tmp_path: Path) -> None:
    """A batch result carrying next_page_token (rare: >1 page of advisories
    for one package) falls back to the classic full /v1/query for it."""
    from attackmap.cve import _OSV_BATCH_URL, _OSV_QUERY_URL

    calls: list[tuple[str, bytes]] = []
    full_payload = {"vulns": [_osv_vuln("GHSA-paged-1")]}

    def transport(url: str, body: bytes) -> bytes:
        calls.append((url, body))
        if url == _OSV_BATCH_URL:
            return json.dumps(
                {"results": [{"vulns": [{"id": "GHSA-paged-1", "modified": ""}], "next_page_token": "tok"}]}
            ).encode("utf-8")
        if url == _OSV_QUERY_URL:
            return json.dumps(full_payload).encode("utf-8")
        raise AssertionError(f"unexpected URL {url}")

    vulns, summary = query_vulnerabilities([_dep()], cache_dir=tmp_path, transport=transport)
    assert [v.id for v in vulns] == ["GHSA-paged-1"]
    assert any(c[0] == _OSV_QUERY_URL for c in calls)


def test_query_reports_determinate_progress(tmp_path: Path) -> None:
    """The progress sink sees begin(total=unique packages) and one advance
    per package — cache hits and network results alike."""

    class _FakeProgress:
        def __init__(self) -> None:
            self.begun: tuple[int, str] | None = None
            self.advanced: list[str] = []

        def begin(self, total: int, label: str = "") -> None:
            self.begun = (total, label)

        def advance(self, current: str = "") -> None:
            self.advanced.append(current)

    transport, _ = _stub_transport({"pkg-a": {"vulns": [_osv_vuln()]}})
    deps = [_dep(name="pkg-a"), _dep(name="pkg-b"), _dep(name="pkg-b")]  # 2 unique
    sink = _FakeProgress()
    query_vulnerabilities(deps, cache_dir=tmp_path, transport=transport, progress=sink)
    assert sink.begun is not None and sink.begun[0] == 2
    assert len(sink.advanced) == 2

    # A warm-cache rerun advances through every package instantly.
    sink2 = _FakeProgress()
    query_vulnerabilities(deps, cache_dir=tmp_path, transport=transport, progress=sink2)
    assert sink2.begun is not None and sink2.begun[0] == 2
    assert len(sink2.advanced) == 2


# ---------------------------------------------------------------------------
# Finding emission via threat_model.generate_findings
# ---------------------------------------------------------------------------


def _make_vuln(vid: str = "GHSA-abc", severity: str = "high", cvss: float | None = 8.5) -> Vulnerability:
    return Vulnerability(
        id=vid,
        aliases=["CVE-2023-9999"],
        summary="Path traversal in the sample package.",
        severity=severity,  # type: ignore[arg-type]
        cvss_score=cvss,
        references=["https://example.com/adv"],
        affected_range="affected: >= 0, fixed in 1.2.3",
        package_name="express",
        package_version="4.16.0",
        ecosystem="npm",
    )


def test_vulnerability_produces_finding_with_expected_tags() -> None:
    scan = ScanResult(root="/", vulnerabilities=[_make_vuln()])
    findings = generate_findings(scan)
    matches = [f for f in findings if "cve" in f.tags]
    assert matches
    finding = matches[0]
    assert "express@4.16.0" in finding.title
    assert "npm" in finding.title
    assert finding.severity == "high"
    assert "dependency" in finding.tags
    assert "npm" in finding.tags
    assert any("GHSA-abc" in line for line in finding.evidence)
    assert any("CVE-2023-9999" in line for line in finding.evidence)


def test_multiple_vulns_on_one_dep_aggregate_into_one_finding() -> None:
    scan = ScanResult(
        root="/",
        vulnerabilities=[
            _make_vuln(vid="GHSA-a", severity="high", cvss=9.0),
            _make_vuln(vid="GHSA-b", severity="medium", cvss=5.0),
        ],
    )
    findings = [f for f in generate_findings(scan) if "cve" in f.tags]
    assert len(findings) == 1
    ev = "\n".join(findings[0].evidence)
    assert "GHSA-a" in ev
    assert "GHSA-b" in ev
    # Highest severity wins the Finding-level severity.
    assert findings[0].severity == "high"


def test_multiple_deps_emit_separate_findings() -> None:
    scan = ScanResult(
        root="/",
        vulnerabilities=[
            _make_vuln(vid="GHSA-a"),
            Vulnerability(
                id="GHSA-c",
                package_name="lodash",
                package_version="4.17.20",
                ecosystem="npm",
                severity="medium",
            ),
        ],
    )
    findings = [f for f in generate_findings(scan) if "cve" in f.tags]
    titles = {f.title for f in findings}
    assert any("express" in t for t in titles)
    assert any("lodash" in t for t in titles)


def test_no_vulnerabilities_produces_no_cve_findings() -> None:
    scan = ScanResult(root="/", dependencies=[_dep()])
    findings = [f for f in generate_findings(scan) if "cve" in f.tags]
    assert findings == []


# ---------------------------------------------------------------------------
# CLI wiring: --cve flag
# ---------------------------------------------------------------------------


def test_cli_cve_off_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='x'\ndependencies=['flask>=3.0']\n", encoding="utf-8")

    called: list[tuple] = []

    def stub_query(*args, **kwargs):
        called.append((args, kwargs))
        return [], LookupSummary()

    monkeypatch.setattr("attackmap.cli.query_vulnerabilities", stub_query)
    result = runner.invoke(app, ["analyze", str(repo), "--output", str(tmp_path / "out")])
    assert result.exit_code == 0
    assert called == []  # --cve not passed → lookup never runs


def test_cli_cve_flag_triggers_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        "[project]\nname='x'\ndependencies=['flask>=3.0']\n", encoding="utf-8"
    )

    def stub_query(deps, **kwargs):
        summary = LookupSummary(queried=len(list(deps)))
        return [_make_vuln()], summary

    monkeypatch.setattr("attackmap.cli.query_vulnerabilities", stub_query)
    result = runner.invoke(
        app, ["analyze", str(repo), "--output", str(tmp_path / "out"), "--cve"]
    )
    assert result.exit_code == 0
    assert "Checking" in result.stdout
    assert "CVE lookup" in result.stdout
    report = json.loads((tmp_path / "out" / "attackmap-report.json").read_text(encoding="utf-8"))
    # Vulnerabilities from the stub end up on scan.vulnerabilities in the JSON report.
    assert report["scan"]["vulnerabilities"]
    cve_findings = [f for f in report["findings"] if "cve" in f.get("tags", [])]
    assert cve_findings


def test_cli_cve_with_no_deps_does_not_call_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "readme.md").write_text("no deps here\n", encoding="utf-8")

    called: list[tuple] = []

    def stub_query(*args, **kwargs):
        called.append((args, kwargs))
        return [], LookupSummary()

    monkeypatch.setattr("attackmap.cli.query_vulnerabilities", stub_query)
    result = runner.invoke(app, ["analyze", str(repo), "--output", str(tmp_path / "out"), "--cve"])
    assert result.exit_code == 0
    assert called == []


# ---------------------------------------------------------------------------
# Transitive dependency provenance (#143)
# ---------------------------------------------------------------------------


def test_transitive_dep_vuln_carries_resolution_path(tmp_path: Path) -> None:
    """A vulnerable transitive dep resolved from a lockfile flows through the
    lookup with its resolution path attached (AC2)."""
    transitive = DependencyHint(
        name="sample-pkg",
        version="1.0.0",
        ecosystem="pypi",
        file="poetry.lock",
        resolved=True,
        direct=False,
        via="flask > jinja2 > sample-pkg",
    )
    transport, _ = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    vulns, _ = query_vulnerabilities([transitive], cache_dir=tmp_path, transport=transport)
    assert len(vulns) == 1
    assert vulns[0].direct is False
    assert vulns[0].resolution_path == "flask > jinja2 > sample-pkg"


def test_transitive_vuln_finding_cites_resolution_path(tmp_path: Path) -> None:
    scan = ScanResult(
        root="/",
        vulnerabilities=[
            Vulnerability(
                id="GHSA-test-1234",
                summary="Path traversal.",
                severity="high",
                package_name="sample-pkg",
                package_version="1.0.0",
                ecosystem="pypi",
                direct=False,
                resolution_path="flask > jinja2 > sample-pkg",
            )
        ],
    )
    findings = [f for f in generate_findings(scan) if "cve" in f.tags]
    assert findings
    joined = "\n".join(findings[0].evidence)
    assert "flask > jinja2 > sample-pkg" in joined
    assert "ransitive" in joined  # "Transitive ... resolution path"


def test_resolved_exact_version_is_queried_verbatim(tmp_path: Path) -> None:
    """A lockfile-resolved exact version is queried as-is (not guessed)."""
    dep = DependencyHint(
        name="sample-pkg", version="1.2.4", ecosystem="pypi",
        file="poetry.lock", resolved=True, direct=True,
    )
    transport, calls = _stub_transport({"sample-pkg": {"vulns": []}})
    query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport)
    assert calls, "expected one OSV query"
    assert '"version": "1.2.4"' in calls[0][1].decode("utf-8")


def test_transitive_dep_offline_served_from_warm_cache(tmp_path: Path) -> None:
    """AC3: once cached, a transitive dep's CVE resolves offline."""
    dep = DependencyHint(
        name="sample-pkg", version="1.0.0", ecosystem="pypi",
        file="poetry.lock", resolved=True, direct=False, via="a > b > sample-pkg",
    )
    warm_transport, _ = _stub_transport({"sample-pkg": {"vulns": [_osv_vuln()]}})
    v1, s1 = query_vulnerabilities([dep], cache_dir=tmp_path, transport=warm_transport)
    assert s1.queried == 1 and len(v1) == 1

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("network down")

    v2, s2 = query_vulnerabilities([dep], cache_dir=tmp_path, transport=offline)
    assert s2.cached == 1
    assert len(v2) == 1
    assert v2[0].resolution_path == "a > b > sample-pkg"


def test_resolved_pep440_version_not_mangled(tmp_path: Path) -> None:
    """A lockfile-pinned PEP 440 version (e.g. 1.0.post1) is queried verbatim,
    not normalized to 1.0.0 (#143)."""
    dep = DependencyHint(
        name="sample-pkg", version="1.0.post1", ecosystem="pypi",
        file="poetry.lock", resolved=True, direct=True,
    )
    transport, calls = _stub_transport({"sample-pkg": {"vulns": []}})
    query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport)
    assert calls
    assert '"version": "1.0.post1"' in calls[0][1].decode("utf-8")
