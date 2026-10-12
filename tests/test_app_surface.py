"""App attack-surface contract (#188, #190): plugins emit `AppSurfaceIssue`,
core turns each kind into one aggregated finding with taxonomy."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap import analyzers as analyzers_mod
from attackmap import sdk
from attackmap.analyzers import (
    analyzer_install_url,
    merge_analyzer_results,
    official_plugin,
    select_requested_analyzers,
)
from attackmap.models import APP_SURFACE_ISSUE_KINDS, AppSurfaceIssue, ScanResult
from attackmap.recon_to_analysis import translate_recon
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import _APP_SURFACE_FINDING_SPEC, rule_catalog


def _findings(*issues: AppSurfaceIssue):
    scan = ScanResult(root=".", app_surface_issues=list(issues))
    return [f for f in translate_recon(scan).findings if (f.rule_id or "").startswith("apple-")]


def test_sdk_exports_the_contract() -> None:
    assert sdk.AppSurfaceIssue is AppSurfaceIssue
    assert set(sdk.APP_SURFACE_ISSUE_KINDS) == set(APP_SURFACE_ISSUE_KINDS)
    issue = sdk.AppSurfaceIssue(kind="apple_ats_insecure_loads", file="Info.plist", line=3)
    assert issue.severity == "medium"


def test_every_kind_has_a_spec_catalog_entry_and_taxonomy() -> None:
    assert set(_APP_SURFACE_FINDING_SPEC) == set(APP_SURFACE_ISSUE_KINDS)
    catalog = {r for r, _, _ in rule_catalog()}
    for kind in APP_SURFACE_ISSUE_KINDS:
        rule_id = kind.replace("_", "-")
        assert rule_id in catalog
        entry = taxonomy_for(rule_id)
        assert entry is not None and entry.cwe and entry.owasp


def test_unknown_kind_is_rejected() -> None:
    with pytest.raises(ValueError):
        AppSurfaceIssue(kind="apple_something_else", file="x")  # type: ignore[arg-type]


def test_one_finding_per_kind_at_the_worst_severity() -> None:
    findings = _findings(
        AppSurfaceIssue(kind="apple_ats_insecure_loads", file="Ext/Info.plist", line=9, severity="low",
                        evidence_text="NSExceptionDomains.example.com.NSExceptionAllowsInsecureHTTPLoads = true"),
        AppSurfaceIssue(kind="apple_ats_insecure_loads", file="App/Info.plist", line=4, severity="medium",
                        evidence_text="NSAppTransportSecurity.NSAllowsArbitraryLoads = true"),
        AppSurfaceIssue(kind="apple_custom_url_scheme", file="App/Info.plist", line=20, severity="low"),
    )
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"apple-ats-insecure-loads", "apple-custom-url-scheme"}
    ats = by_rule["apple-ats-insecure-loads"]
    assert ats.severity == "medium"
    assert ats.confidence == "high"
    # The worst instance leads the evidence.
    assert ats.evidence[0].startswith("App/Info.plist:4 — NSAppTransportSecurity.NSAllowsArbitraryLoads")
    assert {(loc.file, loc.line) for loc in ats.locations} == {("App/Info.plist", 4), ("Ext/Info.plist", 9)}
    assert "app-surface" in ats.tags
    assert "external/cwe/cwe-319" in ats.tags
    assert ats.taxonomy is not None and ats.taxonomy.cwe == ["CWE-319"]
    assert [t.technique_id for t in ats.attack_techniques] == ["T1557"]
    assert by_rule["apple-custom-url-scheme"].taxonomy.cwe == ["CWE-939"]


def test_no_issues_no_findings() -> None:
    assert _findings() == []


def test_evidence_is_capped_and_redacted() -> None:
    issues = [AppSurfaceIssue(kind="apple_dynamic_dispatch", file=f"F{i}.m", line=i) for i in range(12)]
    finding = _findings(*issues)[0]
    assert len(finding.evidence) == 11 and finding.evidence[-1] == "+2 more occurrence(s)"
    secret = AppSurfaceIssue(kind="apple_pasteboard_secret", file="A.swift", line=1,
                             evidence_text='UIPasteboard.general.string = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"')
    assert "A1b2C3d4E5f6G7h8I9j0" not in (secret.evidence_text or "")


def test_merge_dedups_plugin_issues_by_kind_file_line() -> None:
    a = ScanResult(root=".", app_surface_issues=[AppSurfaceIssue(kind="apple_custom_url_scheme", file="Info.plist", line=5)])
    b = ScanResult(root=".", app_surface_issues=[
        AppSurfaceIssue(kind="apple_custom_url_scheme", file="Info.plist", line=5),
        AppSurfaceIssue(kind="apple_custom_url_scheme", file="Info.plist", line=9),
    ])
    merged = merge_analyzer_results([a, b], root=".")
    assert [(i.file, i.line) for i in merged.app_surface_issues] == [("Info.plist", 5), ("Info.plist", 9)]


# ---------- one package, several analyzer entry points (#190) ----------

_LOCK = [
    {"repo": "attackmap-analyzer-swift", "package": "attackmap-analyzer-swift", "version": "0.2.0",
     "git_sha": "a" * 40, "entry_points": ["objc", "swift"]},
    {"repo": "attackmap-analyzer-java-spring", "package": "attackmap-analyzer-java-spring", "version": "0.1.0",
     "git_sha": "b" * 40, "entry_points": ["java_spring"]},
    {"repo": "attack-map-analyzer-omeka-s", "package": "attackmap-analyzer-omeka-s", "version": "0.1.0",
     "git_sha": "c" * 40, "entry_points": ["omeka_s"]},
]


@pytest.fixture
def lock(monkeypatch):
    monkeypatch.setattr(analyzers_mod, "_OFFICIAL_BY_PACKAGE", {e["package"]: e for e in _LOCK})
    monkeypatch.setattr(analyzers_mod, "_OFFICIAL_BY_ENTRY_POINT", {
        ep.replace("_", "-"): e for e in _LOCK for ep in e["entry_points"]
    })


def test_a_second_entry_point_resolves_to_its_package(lock) -> None:
    assert official_plugin("objc")["package"] == "attackmap-analyzer-swift"
    assert official_plugin("swift")["package"] == "attackmap-analyzer-swift"
    assert official_plugin("attackmap-analyzer-objc")["package"] == "attackmap-analyzer-swift"
    assert official_plugin("java-spring")["package"] == "attackmap-analyzer-java-spring"
    assert official_plugin("java_spring")["package"] == "attackmap-analyzer-java-spring"
    assert official_plugin("nope") is None
    assert analyzer_install_url("objc") == (
        f"attackmap-analyzer-swift @ git+https://github.com/mlaify/attackmap-analyzer-swift.git@{'a' * 40}"
    )


def test_auto_install_installs_a_shared_package_once(lock, monkeypatch) -> None:
    class _Fake:
        def __init__(self, name: str) -> None:
            self._name = name
            self.metadata = sdk.AnalyzerMetadata(name=name)

        @property
        def name(self) -> str:
            return self._name

        def analyze(self, root: str | Path) -> ScanResult:
            return ScanResult(root=str(root))

    installed: list[str] = []
    monkeypatch.setattr(
        analyzers_mod, "get_registered_analyzers",
        lambda: [_Fake("swift"), _Fake("objc")] if installed else [],
    )
    selected = select_requested_analyzers(["swift", "objc"], auto_install=True, installer=installed.append)
    assert installed == ["attackmap-analyzer-swift"]
    assert [a.name for a in selected] == ["swift", "objc"]

    # The package name is what gets installed, also when it differs from the repo.
    installed.clear()
    monkeypatch.setattr(analyzers_mod, "get_registered_analyzers", lambda: [_Fake("omeka-s")] if installed else [])
    select_requested_analyzers(["omeka-s"], auto_install=True, installer=installed.append)
    assert installed == ["attackmap-analyzer-omeka-s"]
