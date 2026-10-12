"""Plugin-emitted native C/C++ weakness records (#189) and the cmake SBOM
ecosystem (#191): model, SDK surface, merge, findings and taxonomy."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap import sdk
from attackmap.analyzers import merge_analyzer_results
from attackmap.cve import INVENTORY_ONLY_ECOSYSTEMS, query_vulnerabilities
from attackmap.models import NATIVE_WEAKNESS_KINDS, CodeWeakness, DependencyHint, ScanResult
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import generate_findings, rule_catalog

NATIVE_RULES = {k.replace("_", "-") for k in NATIVE_WEAKNESS_KINDS}


def _w(kind: str, severity: str, line: int, *, confidence: str | None = None, source: str | None = None) -> CodeWeakness:
    return CodeWeakness(
        kind=kind,  # type: ignore[arg-type]
        file="src/server.c",
        line=line,
        evidence_text=f"call at {line}",
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
    scan = ScanResult(root=".", code_weaknesses=[CodeWeakness(kind="xxe", file="a.py", line=1, severity="low")])
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
    b = ScanResult(root=".", code_weaknesses=[_w("alloc_size_overflow", "high", 7), _w("tainted_copy_length", "medium", 8)])
    merged = merge_analyzer_results([a, b], root=".")
    assert [(w.kind, w.line, w.source_kind) for w in merged.code_weaknesses] == [
        ("alloc_size_overflow", 7, "network"),
        ("tainted_copy_length", 8, None),
    ]


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
