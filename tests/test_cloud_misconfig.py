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


def test_unknown_kind_and_out_of_range_confidence_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _issue("not_a_kind")
    with pytest.raises(ValidationError):
        _issue(confidence=1.5)


def test_one_finding_per_kind_with_the_worst_instance_first() -> None:
    findings = _findings(
        _issue("host_path_mount", line=40, severity="low", confidence=0.6, evidence_text="path: /var/log"),
        _issue(
            "host_path_mount", line=31, severity="high", confidence=0.95,
            evidence_text="path: /var/run/docker.sock",
            escalation_path="Docker socket → root on the node",
        ),
        _issue("privileged_container", line=20, severity="high", context="Helm template"),
    )
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"host-path-mount", "privileged-container"}

    mount = by_rule["host-path-mount"]
    assert mount.severity == "high" and mount.confidence == "high"
    assert mount.evidence[0] == (
        "k8s/app.yaml:31 [Deployment/app container web] — path: /var/run/docker.sock"
        " → Docker socket → root on the node"
    )
    assert mount.evidence[1].endswith("— path: /var/log")
    assert [(loc.file, loc.line) for loc in mount.locations] == [("k8s/app.yaml", 31), ("k8s/app.yaml", 40)]
    assert "cloud-misconfig" in mount.tags and "external/cwe/cwe-668" in mount.tags
    assert mount.taxonomy is not None and mount.taxonomy.cwe[0] == "CWE-668"
    assert [t.technique_id for t in mount.attack_techniques] == ["T1611"]
    assert "(Helm template)" in by_rule["privileged-container"].evidence[0]


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
