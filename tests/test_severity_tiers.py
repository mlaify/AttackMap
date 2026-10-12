"""Shared pieces for detector families whose records carry their own
severity (CloudMisconfig now; native CodeWeakness kinds next): tiered
findings and titles, SARIF rule metadata from a spec's default tier,
cross-finding fingerprint occurrences, keep-more-severe merging and the
drop-and-note pattern for `str` kinds."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from attackmap import analyzers, threat_model
from attackmap.fingerprint import assign_fingerprints
from attackmap.merge import keep_more_severe
from attackmap.models import CloudMisconfig, Finding, FindingLocation, ScanResult
from attackmap.sarif import build_sarif

_SPEC = {"tier": "high", "title": "Thing is risky", "mitigation": "Fix it."}


def _rec(severity: str, confidence: float, line: int) -> SimpleNamespace:
    return SimpleNamespace(severity=severity, confidence=confidence, file="a.py", line=line)


def _tiered(*records):
    return threat_model.tiered_findings(
        "thing_risky", _SPEC, list(records),
        evidence=lambda r: f"{r.file}:{r.line}",
        locations=lambda items: [FindingLocation(file=r.file, line=r.line) for r in items],
        tags=["novel-vuln"],
    )


def test_tier_title_depends_only_on_the_tier() -> None:
    assert threat_model.tier_title("T", "high", "high") == "T"
    assert threat_model.tier_title("T", "low", "high") == "T (low-severity instances)"
    assert threat_model.tier_title("T", "high", "medium") == "T (high-severity instances)"


def test_tiered_findings_split_and_take_confidence_per_tier() -> None:
    findings = _tiered(_rec("high", 0.4, 1), _rec("low", 0.9, 2), _rec("low", 0.5, 3))
    by_sev = {f.severity: f for f in findings}
    assert set(by_sev) == {"high", "low"}
    assert by_sev["high"].title == "Thing is risky" and by_sev["high"].confidence == "low"
    assert by_sev["low"].title == "Thing is risky (low-severity instances)" and by_sev["low"].confidence == "high"
    assert by_sev["low"].evidence == ["a.py:2", "a.py:3"]  # most confident first
    assert {f.rule_id for f in findings} == {"thing-risky"}


def test_sarif_rule_metadata_uses_the_default_tier_for_any_tiered_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    # Not gated on a tag: any spec table registered as tiered works.
    monkeypatch.setattr(threat_model, "_TIERED_SPEC_TABLES", ({"thing_risky": _SPEC},))
    findings = _tiered(_rec("low", 0.9, 2), _rec("high", 0.9, 1))
    findings.sort(key=lambda f: f.severity != "low")  # low tier listed first
    (rule,) = build_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    assert rule["name"] == "Thing is risky"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "9.0"


def test_fingerprints_count_occurrences_across_findings_of_a_rule() -> None:
    a = Finding(title="A", severity="high", mitigation="m", rule_id="r", locations=[FindingLocation(file="x.py")])
    b = Finding(title="A (low-severity instances)", severity="low", mitigation="m", rule_id="r",
                locations=[FindingLocation(file="x.py")])
    other = Finding(title="B", severity="low", mitigation="m", rule_id="s", locations=[FindingLocation(file="x.py")])
    assign_fingerprints([a, b, other], ".")
    prints = {a.locations[0].fingerprint, b.locations[0].fingerprint}
    assert len(prints) == 2
    assert other.locations[0].fingerprint not in prints


@pytest.mark.parametrize(
    "existing, duplicate, expected",
    [
        (("low", 0.9), ("high", 0.2), ("high", 0.2)),
        (("high", 0.5), ("high", 0.8), ("high", 0.8)),
        (("high", 0.8), ("medium", 0.99), ("high", 0.8)),
        (("medium", "low"), ("medium", "high"), ("medium", "high")),
    ],
)
def test_keep_more_severe(existing, duplicate, expected) -> None:
    kept = SimpleNamespace(severity=existing[0], confidence=existing[1])
    keep_more_severe(kept, SimpleNamespace(severity=duplicate[0], confidence=duplicate[1]))
    assert (kept.severity, kept.confidence) == expected


def test_kind_vocabularies_drive_the_unknown_kind_drop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        analyzers, "KIND_VOCABULARIES", (("cloud_misconfigs", frozenset({"rbac_wildcard"}), "UnknownTestKind"),)
    )
    result = ScanResult(root=".", cloud_misconfigs=[
        CloudMisconfig(kind="rbac_wildcard", file="a"), CloudMisconfig(kind="privileged_container", file="b"),
    ])
    (note,) = analyzers.drop_unknown_kinds(result, "plug")
    assert note.error_type == "UnknownTestKind" and "privileged_container" in note.message
    assert [m.kind for m in result.cloud_misconfigs] == ["rbac_wildcard"]
    assert analyzers.drop_unknown_kinds(result, "plug") == []


def test_winning_duplicate_brings_its_fields_and_provenance() -> None:
    """#359: the merged record mustn't pair one analyzer's severity with
    another's escalation path or `source_analyzer`."""
    from attackmap.analyzers import merge_analyzer_results
    from attackmap.models import AppSurfaceIssue

    def result(analyzer: str, severity: str, confidence: float, path: str) -> ScanResult:
        return ScanResult(
            root=".",
            cloud_misconfigs=[CloudMisconfig(
                kind="host_path_mount", file="k8s/agent.yaml", line=7, resource="Deployment/agent",
                evidence_text="hostPath mount", severity=severity, confidence=confidence,
                escalation_path=path, context=f"{analyzer} context", source_analyzer=analyzer,
            )],
            app_surface_issues=[AppSurfaceIssue(
                kind="apple_ats_insecure_loads", file="Info.plist", line=None, evidence_text="NSAllowsArbitraryLoads",
                severity=severity, confidence=confidence, source_analyzer=analyzer,
            )],
        )

    merged = merge_analyzer_results([
        result("iac", "medium", 0.6, "read logs"),
        result("terraform", "high", 0.9, "docker.sock -> host root"),
    ])
    (cloud,) = merged.cloud_misconfigs
    assert (cloud.severity, cloud.confidence, cloud.escalation_path, cloud.context, cloud.source_analyzer) == (
        "high", 0.9, "docker.sock -> host root", "terraform context", "terraform",
    )
    (surface,) = merged.app_surface_issues
    assert (surface.severity, surface.source_analyzer) == ("high", "terraform")

    # The weaker duplicate arriving second changes nothing.
    merged = merge_analyzer_results([
        result("terraform", "high", 0.9, "docker.sock -> host root"),
        result("iac", "medium", 0.6, "read logs"),
    ])
    assert merged.cloud_misconfigs[0].source_analyzer == "terraform"
    assert merged.cloud_misconfigs[0].escalation_path == "docker.sock -> host root"
