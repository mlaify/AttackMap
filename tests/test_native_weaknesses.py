"""Plugin-emitted native C/C++ weakness records (#189) and the cmake SBOM
ecosystem (#191): model, SDK surface, merge, findings and taxonomy."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap import sdk
from attackmap.analyzers import drop_unknown_kinds, merge_analyzer_results
from attackmap.cve import INVENTORY_ONLY_ECOSYSTEMS, query_vulnerabilities
from attackmap.diff import finding_id
from attackmap.fingerprint import assign_fingerprints
from attackmap.models import NATIVE_WEAKNESS_KINDS, CodeWeakness, DependencyHint, ScanResult
from attackmap.sarif import build_sarif
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import generate_findings, rule_catalog, tiered_rule_defaults

NATIVE_RULES = {k.replace("_", "-") for k in NATIVE_WEAKNESS_KINDS}


def _w(
    kind: str, severity: str, line: int, *, confidence: str | None = None, source: str | None = None,
    evidence: str | None = None,
) -> CodeWeakness:
    return CodeWeakness(
        kind=kind,
        file="src/server.c",
        line=line,
        evidence_text=evidence or f"call at {line}",
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        source_kind=source,
        source_line=line - 2 if source else None,
    )


def _native(findings, rule: str):
    return sorted((f for f in findings if f.rule_id == rule), key=lambda f: f.severity)


def test_sdk_exports_weakness_and_supply_chain_records() -> None:
    assert set(NATIVE_WEAKNESS_KINDS) <= set(sdk.CODE_WEAKNESS_KINDS)
    assert {"CodeWeakness", "CODE_WEAKNESS_KINDS", "SupplyChainIssue"} <= set(sdk.__all__)
    issue = sdk.SupplyChainIssue(kind="mutable_vcs_dependency", file="CMakeLists.txt", package="json")
    assert issue.severity == "medium"
    weakness = sdk.CodeWeakness(kind="format_string", file="a.c", source_kind="request", confidence="high")
    assert weakness.confidence == "high" and weakness.source_line is None


def test_confidence_is_optional_and_validated() -> None:
    assert CodeWeakness(kind="xxe", file="a.py").confidence is None
    with pytest.raises(ValueError):
        CodeWeakness(kind="format_string", file="a.c", confidence="certain")  # type: ignore[arg-type]


def test_source_kind_is_validated_and_source_line_needs_a_source() -> None:
    w = CodeWeakness(kind="format_string", file="a.c", source_kind="x" * 5000 + "\n[input: forged]", source_line=4)
    assert w.source_kind == "other" and w.source_line == 4
    assert CodeWeakness(kind="format_string", file="a.c", source_kind="argv", source_line=0).source_line is None
    assert CodeWeakness(kind="format_string", file="a.c", source_line=9).source_line is None
    native = [f for f in generate_findings(ScanResult(root=".", code_weaknesses=[_w("format_string", "high", 9, source="bogus")])) if f.rule_id == "format-string"]
    assert native[0].evidence == ["src/server.c:9 — call at 9 [input: other input (line 7)]"]


def test_tier_ids_are_stable_across_reruns_and_added_instances() -> None:
    base = [_w("unbounded_copy", "high", 20, confidence="high", source="request")]
    first = {f.severity: finding_id(f.title) for f in generate_findings(ScanResult(root=".", code_weaknesses=base)) if f.rule_id == "unbounded-copy"}
    more = base + [_w("unbounded_copy", "low", 30, confidence="low")]
    second = {f.severity: finding_id(f.title) for f in generate_findings(ScanResult(root=".", code_weaknesses=more)) if f.rule_id == "unbounded-copy"}
    assert second["high"] == first["high"] and second["low"] != second["high"]


def test_fingerprints_differ_across_tiers_on_one_line(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.c").write_text("\n" * 9 + "strcpy(a, req); strcpy(b, \"x\");\n")
    items = [
        _w("unbounded_copy", "high", 10, confidence="high", source="request", evidence="strcpy(a, req)"),
        _w("unbounded_copy", "low", 10, confidence="low", evidence="strcpy(b, x)"),
    ]
    findings = _native(generate_findings(ScanResult(root=".", code_weaknesses=items)), "unbounded-copy")
    assign_fingerprints(findings, tmp_path)
    fps = [loc.fingerprint for f in findings for loc in f.locations]
    assert len(fps) == 2 and len(set(fps)) == 2 and None not in fps
    # A rerun yields the same fingerprints.
    again = _native(generate_findings(ScanResult(root=".", code_weaknesses=items)), "unbounded-copy")
    assign_fingerprints(again, tmp_path)
    assert [loc.fingerprint for f in again for loc in f.locations] == fps
    sarif = build_sarif(findings)["runs"][0]
    assert len(sarif["results"]) == 2


def test_sarif_rule_metadata_comes_from_the_default_tier() -> None:
    items = [_w("tainted_copy_length", "low", 3, confidence="low"), _w("tainted_copy_length", "high", 4, confidence="high", source="network")]
    findings = _native(generate_findings(ScanResult(root=".", code_weaknesses=items)), "tainted-copy-length")
    findings.sort(key=lambda f: f.severity != "low")  # low tier first
    (rule,) = [r for r in build_sarif(findings)["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "tainted-copy-length"]
    title, tier, _ = tiered_rule_defaults("tainted-copy-length")
    assert rule["name"] == title and tier == "high"
    assert rule["defaultConfiguration"]["level"] == "error"


def test_unknown_kind_and_ecosystem_are_dropped_with_a_note() -> None:
    result = ScanResult(
        root=".",
        code_weaknesses=[CodeWeakness(kind="use_after_free_v2", file="a.c"), _w("format_string", "low", 2)],
        dependencies=[
            DependencyHint(name="zlib", version="1.3", ecosystem="cmake", file="CMakeLists.txt"),
            DependencyHint(name="foo", version="1", ecosystem="bazel_future", file="MODULE.bazel"),
        ],
    )
    notes = drop_unknown_kinds(result, "plug")
    assert sorted(n.error_type for n in notes) == ["UnknownCodeWeaknessKind", "UnknownDependencyEcosystem"]
    assert [w.kind for w in result.code_weaknesses] == ["format_string"]
    assert [d.name for d in result.dependencies] == ["zlib"]
    assert any("use_after_free_v2" in n.message for n in notes)


def test_native_findings_split_per_severity_tier() -> None:
    scan = ScanResult(
        root=".",
        code_weaknesses=[
            _w("unbounded_copy", "low", 40, confidence="low"),
            _w("unbounded_copy", "high", 20, confidence="high", source="request"),
            _w("unbounded_copy", "low", 30, confidence="low"),
            _w("unbounded_copy", "medium", 50, confidence="medium", source="argv"),
        ],
    )
    copies = _native(generate_findings(scan), "unbounded-copy")
    assert [f.severity for f in copies] == ["high", "low", "medium"]
    high, low, medium = copies
    # Each tier has its own title, hence its own finding id (#333 review).
    assert high.title == "Unbounded buffer copy (strcpy/strcat/sprintf/gets)"
    assert low.title.endswith("(low-severity instances)") and medium.title.endswith("(medium-severity instances)")
    assert len({finding_id(f.title) for f in copies}) == 3
    assert high.confidence == "high" and low.confidence == "low" and medium.confidence == "medium"
    # The high tier carries only its own instance, with the traced input named.
    assert [loc.line for loc in high.locations] == [20]
    assert high.evidence == ["src/server.c:20 — call at 20 [input: request input (line 18)]"]
    assert [loc.line for loc in low.locations] == [30, 40]
    assert all(e.endswith("[no input source traced]") for e in low.evidence)
    assert medium.evidence[0].endswith("[input: command-line argument (line 48)]")
    assert {"native", "memory-safety", "novel-vuln"} <= set(high.tags)


def test_command_exec_is_not_tagged_memory_safety() -> None:
    scan = ScanResult(root=".", code_weaknesses=[_w("native_command_exec", "high", 9, confidence="high", source="network")])
    (finding,) = _native(generate_findings(scan), "native-command-exec")
    assert "memory-safety" not in finding.tags and "native" in finding.tags
    assert finding.taxonomy is not None and finding.taxonomy.cwe == ["CWE-78"]
    assert finding.attack_techniques[0].technique_id == "T1059.004"


def test_tier_evidence_is_capped_and_traced_first() -> None:
    items = [_w("format_string", "medium", n, confidence="medium") for n in range(100, 112)]
    items.append(_w("format_string", "medium", 5, confidence="high", source="stdin"))
    (finding,) = _native(generate_findings(ScanResult(root=".", code_weaknesses=items)), "format-string")
    assert finding.evidence[0].startswith("src/server.c:5 ")
    assert finding.evidence[-1] == "+3 more occurrence(s)"
    assert len(finding.locations) == 13
    assert finding.confidence == "high"


def test_existing_code_weakness_kinds_keep_fixed_severity_and_medium_confidence() -> None:
    # A confidence set on a core-aggregated kind doesn't change its finding.
    scan = ScanResult(root=".", code_weaknesses=[CodeWeakness(kind="xxe", file="a.py", line=1, severity="low", confidence="high")])
    (finding,) = [f for f in generate_findings(scan) if f.rule_id == "xxe"]
    assert finding.severity == "high" and finding.confidence == "medium"


def test_native_rules_are_catalogued_with_taxonomy() -> None:
    catalog = {r: sev for r, _, sev in rule_catalog()}
    for rule in NATIVE_RULES:
        assert catalog[rule] == "varies"
        entry = taxonomy_for(rule)
        assert entry is not None and entry.cwe and entry.owasp
    assert taxonomy_for("format-string").cwe == (134,)
    assert taxonomy_for("unbounded-copy").cwe[0] == 120
    assert taxonomy_for("alloc-size-overflow").cwe == (680, 190)


def test_plugin_emitted_weaknesses_survive_the_merge() -> None:
    a = ScanResult(root=".", code_weaknesses=[_w("alloc_size_overflow", "high", 7, confidence="high", source="network")])
    b = ScanResult(root=".", code_weaknesses=[_w("alloc_size_overflow", "low", 7, confidence="low"), _w("tainted_copy_length", "medium", 8)])
    merged = merge_analyzer_results([a, b], root=".")
    assert [(w.kind, w.line, w.severity, w.source_kind) for w in merged.code_weaknesses] == [
        ("alloc_size_overflow", 7, "high", "network"),
        ("tainted_copy_length", 8, "medium", None),
    ]


def test_merge_keeps_the_more_severe_report_with_its_source() -> None:
    weak = _w("unbounded_copy", "low", 7, confidence="low")
    strong = _w("unbounded_copy", "high", 7, confidence="high", source="request")
    merged = merge_analyzer_results([ScanResult(root=".", code_weaknesses=[weak]), ScanResult(root=".", code_weaknesses=[strong])], root=".")
    (w,) = merged.code_weaknesses
    assert (w.severity, w.confidence, w.source_kind, w.source_line) == ("high", "high", "request", 5)
    # A weaker duplicate never brings its own source along.
    strong2 = _w("unbounded_copy", "high", 7, confidence="high")
    weak2 = _w("unbounded_copy", "low", 7, confidence="low", source="argv")
    merged = merge_analyzer_results([ScanResult(root=".", code_weaknesses=[strong2]), ScanResult(root=".", code_weaknesses=[weak2])], root=".")
    (w,) = merged.code_weaknesses
    assert (w.severity, w.source_kind, w.source_line) == ("high", None, None)
    # Two different sinks of one kind on one line stay two instances.
    two = [_w("unbounded_copy", "high", 7, evidence="strcpy(a, b)"), _w("unbounded_copy", "low", 7, evidence="strcpy(c, d)")]
    assert len(merge_analyzer_results([ScanResult(root=".", code_weaknesses=two)], root=".").code_weaknesses) == 2
    # Core-aggregated kinds keep the (kind, file, line) identity and the first report.
    xs = [CodeWeakness(kind="xxe", file="a.py", line=1, evidence_text="a", severity="low"),
          CodeWeakness(kind="xxe", file="a.py", line=1, evidence_text="b", severity="high")]
    (x,) = merge_analyzer_results([ScanResult(root=".", code_weaknesses=xs)], root=".").code_weaknesses
    assert (x.evidence_text, x.severity) == ("a", "low")


def test_cmake_dependencies_are_inventory_only(tmp_path: Path) -> None:
    assert "cmake" in sdk.DEPENDENCY_ECOSYSTEMS and "cmake" in INVENTORY_ONLY_ECOSYSTEMS
    dep = DependencyHint(name="nlohmann_json", version="v3.11.3", ecosystem="cmake", file="CMakeLists.txt")
    calls: list[str] = []

    def transport(url: str, body: bytes) -> bytes:
        calls.append(url)
        return b"{}"

    vulns, summary = query_vulnerabilities([dep], cache_dir=tmp_path, transport=transport)
    assert vulns == [] and not calls
    assert summary.inventory_only == {"cmake": 1}
