"""`CloudMisconfig` contract record (terraform#4, iac#1).

IaC plugins report cloud / Kubernetes / container misconfigurations as
`CloudMisconfig` records; core turns each kind into one finding with
CWE/OWASP ids. These tests pin the contract (SDK export, merge, provenance,
redaction) and the finding generation.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from attackmap import sdk
from attackmap.analyzers import BuiltinPythonWebAnalyzer, analyze_repository
from attackmap.models import CLOUD_MISCONFIG_KINDS, CloudMisconfig, ScanResult
from attackmap.recon_to_analysis import translate_recon
from attackmap.sarif import build_sarif
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import _CLOUD_MISCONFIG_FINDING_SPEC, generate_findings, rule_catalog


def _issue(kind: str = "privileged_container", **kw) -> CloudMisconfig:
    base = {"file": "k8s/app.yaml", "line": 12, "resource": "Deployment/app container web", "platform": "kubernetes"}
    return CloudMisconfig(kind=kind, **{**base, **kw})


def _findings(*issues: CloudMisconfig):
    return generate_findings(ScanResult(root=".", cloud_misconfigs=list(issues)))


def test_sdk_exports_the_record_and_its_kinds() -> None:
    assert sdk.CloudMisconfig is CloudMisconfig
    assert sdk.CLOUD_MISCONFIG_KINDS == CLOUD_MISCONFIG_KINDS
    from attackmap.sdk.models import CloudMisconfig as FromModels

    assert FromModels is CloudMisconfig


@pytest.mark.parametrize("kind", CLOUD_MISCONFIG_KINDS)
def test_every_kind_has_a_spec_a_catalog_entry_and_taxonomy(kind: str) -> None:
    rule_id = kind.replace("_", "-")
    assert kind in _CLOUD_MISCONFIG_FINDING_SPEC
    assert rule_id in {r for r, _, _ in rule_catalog()}
    entry = taxonomy_for(rule_id)
    assert entry is not None and entry.cwe and entry.owasp and entry.attack


def test_spec_has_no_kinds_the_model_rejects() -> None:
    assert set(_CLOUD_MISCONFIG_FINDING_SPEC) == set(CLOUD_MISCONFIG_KINDS)


def test_out_of_range_values_and_unknown_platforms_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _issue(confidence=1.5)
    with pytest.raises(ValidationError):
        _issue(platform="openstack")
    with pytest.raises(ValidationError):
        _issue(kind="x" * 65)
    assert set(sdk.CLOUD_MISCONFIG_PLATFORMS) == {
        "aws", "azure", "gcp", "kubernetes", "helm", "compose", "docker", "terraform",
    }


def test_unknown_kind_validates_but_is_not_known() -> None:
    record = _issue("brand_new_kind")  # a plugin built for a newer core
    assert record.kind == "brand_new_kind" and not record.known_kind
    assert _issue().known_kind
    assert not [f for f in _findings(record) if "cloud-misconfig" in f.tags]  # no spec, no finding


def test_one_finding_per_kind_and_severity_tier() -> None:
    findings = _findings(
        _issue("host_path_mount", line=40, severity="low", confidence=0.6, evidence_text="path: /var/log"),
        _issue(
            "host_path_mount", line=31, severity="high", confidence=0.95,
            evidence_text="path: /var/run/docker.sock",
            escalation_path="Docker socket → root on the node",
        ),
        _issue("privileged_container", line=20, severity="high", context="Helm template"),
    )
    by_key = {(f.rule_id, f.severity): f for f in findings}
    assert set(by_key) == {("host-path-mount", "high"), ("host-path-mount", "low"), ("privileged-container", "high")}

    high = by_key[("host-path-mount", "high")]
    assert high.title == "Workload mounts a sensitive host path"  # the kind's usual tier: plain title
    assert high.confidence == "high"
    assert high.evidence == [
        "k8s/app.yaml:31 [Deployment/app container web] — path: /var/run/docker.sock"
        " → Docker socket → root on the node"
    ]
    assert [(loc.file, loc.line) for loc in high.locations] == [("k8s/app.yaml", 31)]
    assert "cloud-misconfig" in high.tags and "external/cwe/cwe-668" in high.tags
    assert high.taxonomy is not None and high.taxonomy.cwe[0] == "CWE-668"
    assert [t.technique_id for t in high.attack_techniques] == ["T1611"]

    low = by_key[("host-path-mount", "low")]
    assert low.title == "Workload mounts a sensitive host path (low-severity instances)"
    assert (low.confidence, [loc.line for loc in low.locations]) == ("medium", [40])
    assert low.evidence[0].endswith("— path: /var/log")
    assert "(Helm template)" in by_key[("privileged-container", "high")].evidence[0]


def test_tier_titles_depend_only_on_the_tier() -> None:
    # Adding a low instance must not rename (re-id) the high finding.
    alone = {f.severity: f.title for f in _findings(_issue("host_path_mount", severity="high"))}
    both = {
        f.severity: f.title
        for f in _findings(_issue("host_path_mount", severity="high"), _issue("host_path_mount", line=99, severity="low"))
    }
    assert alone["high"] == both["high"]


def test_confidence_comes_from_the_records_in_the_tier() -> None:
    findings = _findings(
        _issue("host_path_mount", line=1, severity="high", confidence=0.4),
        _issue("host_path_mount", line=2, severity="low", confidence=0.95),
    )
    by_sev = {f.severity: f.confidence for f in findings}
    assert by_sev == {"high": "low", "low": "high"}


def test_default_confidence_maps_to_a_high_confidence_finding() -> None:
    (finding,) = _findings(_issue("rbac_wildcard", severity="high"))
    assert _issue().confidence == 0.8 and finding.confidence == "high"


def test_two_resources_at_one_location_stay_two_instances() -> None:
    (finding,) = _findings(
        _issue("exposed_service", line=None, severity="low", resource="Service/a"),
        _issue("exposed_service", line=None, severity="low", resource="Service/b"),
    )
    assert len(finding.locations) == 2
    results = build_sarif([finding])["runs"][0]["results"]
    assert len(results) == 1  # unfingerprinted: SARIF can't tell them apart yet
    from attackmap.fingerprint import assign_fingerprints

    assign_fingerprints([finding], ".")
    assert len({loc.fingerprint for loc in finding.locations}) == 2
    assert len(build_sarif([finding])["runs"][0]["results"]) == 2


def test_sarif_level_and_security_severity_follow_each_instance() -> None:
    findings = _findings(
        _issue("host_path_mount", line=31, severity="high", confidence=0.9),
        _issue("host_path_mount", line=40, severity="low", confidence=0.6),
    )
    results = build_sarif(findings)["runs"][0]["results"]
    by_line = {r["locations"][0]["physicalLocation"]["region"]["startLine"]: r for r in results}
    assert by_line[31]["level"] == "error" and by_line[40]["level"] == "note"
    assert float(by_line[40]["properties"]["security-severity"]) < 4.0


def test_diff_gate_ignores_a_new_low_instance_of_a_high_kind() -> None:
    from attackmap.diff import FindingSnapshot, diff_findings
    from attackmap.fingerprint import assign_fingerprints

    def snaps(*issues):
        findings = _findings(*issues)
        assign_fingerprints(findings, ".")
        return [FindingSnapshot.from_finding(f) for f in findings]

    high = _issue("host_path_mount", line=31, severity="high", evidence_text="docker.sock")
    baseline = snaps(high)
    added_low = diff_findings(baseline, snaps(high, _issue("host_path_mount", line=40, severity="low", evidence_text="/var/log")))
    assert not added_low.has_new_high and [s.severity for s in added_low.new] == ["low"]
    added_high = diff_findings(baseline, snaps(high, _issue("host_path_mount", line=50, severity="high", evidence_text="/")))
    assert added_high.has_new_high


def test_free_text_is_one_line_and_capped() -> None:
    record = _issue(
        evidence_text="line one\nline two\r\n\tthree",
        resource="r" * 1000,
        context="c" * 1000,
        escalation_path="e\n" * 400,
    )
    assert record.evidence_text == "line one line two three"
    assert len(record.resource or "") == 200 and record.resource.endswith("…")
    assert len(record.context or "") == 300 and len(record.escalation_path or "") <= 300
    assert "\n" not in (record.escalation_path or "")


def test_low_confidence_records_give_a_low_confidence_finding() -> None:
    (finding,) = _findings(_issue("missing_security_context", severity="low", confidence=0.4))
    assert (finding.severity, finding.confidence) == ("low", "low")


def test_evidence_is_capped_and_counts_the_rest() -> None:
    (finding,) = _findings(*[_issue("exposed_service", line=n, severity="low") for n in range(1, 14)])
    assert len(finding.evidence) == 11 and finding.evidence[-1] == "+3 more occurrence(s)"
    assert len(finding.locations) == 13


def test_evidence_text_is_redacted() -> None:
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    issue = _issue(
        evidence_text=f"token: {secret}",
        context=f"module.net (git::https://oauth2:{secret}@github.com/org/net.git)",
        resource=f"module.{secret}",
        escalation_path=f"uses {secret}",
    )
    for value in (issue.evidence_text, issue.context, issue.resource, issue.escalation_path):
        assert value and secret not in value


def test_no_records_no_findings() -> None:
    assert not [f for f in _findings() if f.rule_id in {k.replace("_", "-") for k in CLOUD_MISCONFIG_KINDS}]


class _IacPlugin:
    """A stand-in IaC plugin returning records the way a real one would."""

    name = "fake-iac"
    metadata = BuiltinPythonWebAnalyzer.metadata.model_copy(update={"name": "fake-iac", "display_name": "fake-iac"})

    def analyze(self, root: Path) -> ScanResult:
        record = _issue("cluster_admin_binding", file="rbac.yaml", line=3, severity="high", resource="ClusterRoleBinding/ci")
        return ScanResult(root=str(root), cloud_misconfigs=[record, record.model_copy()])


def test_plugin_records_merge_get_provenance_and_reach_the_report(tmp_path: Path) -> None:
    (tmp_path / "rbac.yaml").write_text("kind: ClusterRoleBinding\n", encoding="utf-8")
    scan = analyze_repository(tmp_path, analyzers=[_IacPlugin()])
    assert len(scan.cloud_misconfigs) == 1  # deduped on (kind, file, line, resource)
    assert scan.cloud_misconfigs[0].source_analyzer == "fake-iac"

    findings = translate_recon(scan).findings
    finding = next(f for f in findings if f.rule_id == "cluster-admin-binding")
    assert finding.severity == "high" and finding.locations[0].file == "rbac.yaml"
    run = build_sarif(findings, [])["runs"][0]
    assert "cluster-admin-binding" in {r["ruleId"] for r in run["results"]}


def test_dict_results_validate_the_record(tmp_path: Path) -> None:
    class _DictPlugin(_IacPlugin):
        def analyze(self, root: Path):  # type: ignore[override]
            return {"cloud_misconfigs": [{"kind": "rbac_wildcard", "file": "role.yaml", "line": 1}]}

    scan = analyze_repository(tmp_path, analyzers=[_DictPlugin()])
    assert [m.kind for m in scan.cloud_misconfigs] == ["rbac_wildcard"]
    assert scan.cloud_misconfigs[0].severity == "medium"


def test_merge_keeps_two_settings_at_one_line_and_the_worse_duplicate() -> None:
    from attackmap.analyzers import merge_analyzer_results

    low = _issue("host_path_mount", severity="low", confidence=0.6, evidence_text="path: /var/log")
    high = _issue("host_path_mount", severity="high", confidence=0.9, evidence_text="path: /var/run/docker.sock")
    merged = merge_analyzer_results([ScanResult(root=".", cloud_misconfigs=[low]), ScanResult(root=".", cloud_misconfigs=[high])])
    assert sorted(m.severity for m in merged.cloud_misconfigs) == ["high", "low"]

    weaker = _issue("host_path_mount", severity="low", confidence=0.5, evidence_text="path: /")
    stronger = _issue("host_path_mount", severity="high", confidence=0.9, evidence_text="path: /")
    (kept,) = merge_analyzer_results(
        [ScanResult(root=".", cloud_misconfigs=[weaker]), ScanResult(root=".", cloud_misconfigs=[stronger])]
    ).cloud_misconfigs
    assert (kept.severity, kept.confidence) == ("high", 0.9)


class _NewerPlugin(_IacPlugin):
    """Emits a kind this core doesn't know next to a known one and a route."""

    name = "newer-iac"

    def analyze(self, root: Path):  # type: ignore[override]
        return {
            "routes": [{"path": "/x", "method": "GET", "file": "app.py"}],
            "cloud_misconfigs": [
                {"kind": "future_kind", "file": "a.yaml", "line": 1},
                {"kind": "rbac_wildcard", "file": "role.yaml", "line": 2, "severity": "high"},
            ],
        }


def test_unknown_kinds_are_dropped_per_record_and_noted(tmp_path: Path) -> None:
    scan = analyze_repository(tmp_path, analyzers=[_NewerPlugin()])
    assert [r.path for r in scan.routes] == ["/x"]  # the rest of the result survives
    assert [m.kind for m in scan.cloud_misconfigs] == ["rbac_wildcard"]
    (error,) = scan.analyzer_errors
    assert (error.analyzer, error.error_type) == ("newer-iac", "UnknownCloudMisconfigKind")
    assert "future_kind" in error.message


def test_unknown_kinds_fail_fast_in_strict_mode(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="future_kind"):
        analyze_repository(tmp_path, analyzers=[_NewerPlugin()], strict=True)


def test_taxonomy_ids() -> None:
    from attackmap.taxonomy import CWE_NAMES

    assert taxonomy_for("privilege-escalation-allowed").attack == ("T1548.001",)
    assert list(CWE_NAMES) == sorted(CWE_NAMES)
