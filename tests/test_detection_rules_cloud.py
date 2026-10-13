"""Kubernetes audit-log and CloudTrail rules for cloud / IaC misconfigurations (#351)."""

from __future__ import annotations

import re
import time

import pytest
import yaml

from attackmap.analyzer import identify_attack_surfaces
from attackmap.detection_opportunities import detection_coverage, generate_detection_opportunities
from attackmap.detections import rule_yaml, template_data, templates
from attackmap.detections.sigma import sigma_matches, sigma_problems
from attackmap.models import CLOUD_MISCONFIG_KINDS, CloudMisconfig, FindingLocation, ScanResult
from attackmap.taxonomy import RULE_TAXONOMY
from attackmap.threat_model import generate_findings

# Bare event fields: a selection made only of these would match every such
# call, not the risky setting.
_EVENT_ONLY = {"verb", "objectRef.resource", "objectRef.subresource", "eventSource", "eventName"}

_RECORDS = [
    CloudMisconfig(kind="privileged_container", file="k8s/ds.yaml", line=10, platform="kubernetes", resource="DaemonSet/agent"),
    CloudMisconfig(kind="privilege_escalation_allowed", file="k8s/web.yaml", line=20, platform="kubernetes", resource="Deployment/web"),
    CloudMisconfig(kind="dangerous_capability", file="k8s/web.yaml", line=22, platform="kubernetes", resource="Deployment/web"),
    CloudMisconfig(kind="host_path_mount", file="charts/x/templates/ds.yaml", line=30, platform="helm", resource="DaemonSet/{{…}}"),
    CloudMisconfig(kind="host_namespace_shared", file="k8s/ds.yaml", line=12, platform="kubernetes", resource="DaemonSet/agent"),
    CloudMisconfig(kind="exposed_service", file="k8s/svc.yaml", line=5, platform="kubernetes", resource="Service/web"),
    CloudMisconfig(kind="rbac_wildcard", file="k8s/rbac.yaml", line=8, platform="kubernetes", resource="ClusterRole/ops"),
    CloudMisconfig(kind="rbac_escalation", file="k8s/rbac.yaml", line=18, platform="kubernetes", resource="ClusterRole/ops"),
    CloudMisconfig(kind="cluster_admin_binding", file="k8s/rbac.yaml", line=28, platform="kubernetes", resource="ClusterRoleBinding/ops"),
    CloudMisconfig(kind="rbac_secret_access", file="k8s/rbac.yaml", line=38, platform="kubernetes", resource="ClusterRole/reader"),
    CloudMisconfig(kind="public_network_access", file="tf/sg.tf", line=3, platform="aws", resource="aws_security_group.web"),
    CloudMisconfig(kind="public_network_access", file="tf/db.tf", line=4, platform="aws", resource="aws_db_instance.main"),
    CloudMisconfig(kind="public_network_access", file="tf/vm.tf", line=5, platform="aws", resource="aws_instance.bastion"),
    CloudMisconfig(kind="public_data_access", file="tf/s3.tf", line=6, platform="aws", resource="aws_s3_bucket_acl.site"),
    CloudMisconfig(kind="public_cluster_endpoint", file="tf/eks.tf", line=7, platform="aws", resource="aws_eks_cluster.main"),
]


def _opps(records: list[CloudMisconfig], root: str = "/repo/service-a"):
    scan = ScanResult(root=root, cloud_misconfigs=records)
    findings = generate_findings(scan, identify_attack_surfaces(scan))
    return findings, generate_detection_opportunities([], findings, scan, [])


def _cloud(opps):
    return {o.id.removeprefix("detect:cloud:"): o for o in opps if o.id.startswith("detect:cloud:")}


def test_mapping_is_consistent() -> None:
    mapping = template_data("cloud")["mapping"]
    for rule_id, specs in mapping.items():
        assert rule_id.replace("-", "_") in CLOUD_MISCONFIG_KINDS, rule_id
        assert rule_id in RULE_TAXONOMY, rule_id
        for spec in specs:
            assert spec["template"] in templates(), spec


def test_every_cloud_template_is_generated_valid_and_specific() -> None:
    _, opps = _opps(_RECORDS)
    rules = _cloud(opps)
    expected = {spec["template"] for specs in template_data("cloud")["mapping"].values() for spec in specs}
    assert set(rules) == expected
    for name, opp in rules.items():
        assert sigma_problems(opp.sigma) == [], name
        assert opp.test_events.positive
        assert all(sigma_matches(opp.sigma, e) for e in opp.test_events.positive), name
        assert not any(sigma_matches(opp.sigma, e) for e in opp.test_events.negative), name
        # No bare-event rule: some selection the condition needs names a
        # risky attribute (a value field) or a user filter.
        fields = {
            key.split("|")[0]
            for sel_name, sel in opp.sigma["detection"].items()
            if sel_name != "condition"
            for m in (sel if isinstance(sel, list) else [sel])
            for key in m
        }
        assert fields - _EVENT_ONLY, name
        # Round-trips through the YAML export as one document.
        assert list(yaml.safe_load_all(rule_yaml(opp.sigma))) == [opp.sigma]
        for sel in opp.sigma["detection"].values():
            for m in sel if isinstance(sel, list) else [sel] if isinstance(sel, dict) else []:
                for key, value in m.items():
                    if "|re" in key:
                        compiled = re.compile(value)
                        start = time.perf_counter()
                        compiled.search("*" * 20_000 + "x")
                        assert time.perf_counter() - start < 0.05


def test_k8s_rules_match_the_risky_settings() -> None:
    rules = _cloud(_opps(_RECORDS)[1])
    priv = rules["k8s-privileged-workload"].sigma
    assert sigma_matches(priv, {"verb": "create", "objectRef.resource": "pods",
                                "requestObject.spec.containers.securityContext.privileged": True})
    assert not sigma_matches(priv, {"verb": "create", "objectRef.resource": "pods"})
    binding = rules["k8s-cluster-admin-binding"].sigma
    assert not sigma_matches(binding, {"verb": "create", "objectRef.resource": "rolebindings",
                                       "requestObject.roleRef.name": "edit"})
    secrets = rules["k8s-secret-enumeration"].sigma
    assert not sigma_matches(secrets, {"verb": "watch", "objectRef.resource": "secrets",
                                       "user.username": "system:node:ip-10-0-0-1"})
    wildcard = rules["k8s-rbac-wildcard-grant"].sigma
    assert sigma_matches(wildcard, {"verb": "update", "objectRef.resource": "roles", "requestObject.rules.resources": "*"})
    assert not sigma_matches(wildcard, {"verb": "update", "objectRef.resource": "roles", "requestObject.rules.resources": "pods*"})


def test_aws_rules_match_the_risky_settings() -> None:
    rules = _cloud(_opps(_RECORDS)[1])
    sg = rules["aws-security-group-open-ingress"].sigma
    assert sigma_matches(sg, {"eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress",
                              "requestParameters.ipPermissions.items.ipv6Ranges.items.cidrIpv6": "::/0"})
    assert not sigma_matches(sg, {"eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress"})
    s3 = rules["aws-s3-made-public"].sigma
    assert sigma_matches(s3, {"eventSource": "s3-control.amazonaws.com", "eventName": "DeleteAccountPublicAccessBlock"})
    assert not sigma_matches(s3, {"eventSource": "s3.amazonaws.com", "eventName": "PutBucketPolicy"})


def test_rules_follow_platform_and_resource_type() -> None:
    records = [
        CloudMisconfig(kind="privileged_container", file="docker-compose.yml", line=3, platform="compose", resource="service app"),
        CloudMisconfig(kind="public_network_access", file="tf/lb.tf", line=3, platform="aws", resource="aws_lb.public"),
        CloudMisconfig(kind="public_network_access", file="tf/gcp.tf", line=3, platform="gcp", resource="google_compute_firewall.all"),
        CloudMisconfig(kind="public_data_access", file="tf/mod.tf", line=3, platform="terraform", resource="module.bucket"),
    ]
    findings, opps = _opps(records)
    assert {f.rule_id for f in findings} >= {"privileged-container", "public-network-access", "public-data-access"}
    assert _cloud(opps) == {}
    rows = {r["rule_id"]: r["sigma_rules"] for r in detection_coverage(findings, opps)}
    assert rows["privileged-container"] == 0 and rows["public-network-access"] == 0


def test_kinds_without_a_control_plane_event_get_no_rule() -> None:
    records = [
        CloudMisconfig(kind="unencrypted_storage", file="tf/s3.tf", line=1, platform="aws", resource="aws_s3_bucket.logs"),
        CloudMisconfig(kind="unpinned_container_image", file="k8s/web.yaml", line=1, platform="kubernetes", resource="Deployment/web"),
        CloudMisconfig(kind="missing_security_context", file="k8s/web.yaml", line=2, platform="kubernetes", resource="Deployment/web"),
    ]
    assert _cloud(_opps(records)[1]) == {}


def test_suppressed_locations_drop_the_rule() -> None:
    record = CloudMisconfig(kind="cluster_admin_binding", file="k8s/rbac.yaml", line=28, platform="kubernetes",
                            resource="ClusterRoleBinding/ops")
    scan = ScanResult(root="/repo", cloud_misconfigs=[record])
    findings = generate_findings(scan, identify_attack_surfaces(scan))
    for finding in findings:
        if finding.rule_id == "cluster-admin-binding":
            finding.locations = [FindingLocation(file="other.yaml", line=1)]
    assert _cloud(generate_detection_opportunities([], findings, scan, [])) == {}


def test_tiered_findings_are_all_covered() -> None:
    # Two severity tiers of the same kind are two findings; both gate in.
    records = [
        CloudMisconfig(kind="host_path_mount", file="a.yaml", line=1, platform="kubernetes", resource="DaemonSet/a", severity="high"),
        CloudMisconfig(kind="host_path_mount", file="b.yaml", line=1, platform="kubernetes", resource="DaemonSet/b", severity="low"),
    ]
    findings, opps = _opps(records)
    assert len([f for f in findings if f.rule_id == "host-path-mount"]) == 2
    opp = _cloud(opps)["k8s-host-access-workload"]
    assert "DaemonSet/a" in opp.sigma["description"] and "DaemonSet/b" in opp.sigma["description"]


def test_ids_are_stable_and_differ_between_repositories() -> None:
    a = _cloud(_opps(_RECORDS, "/r/service-a")[1])
    again = _cloud(_opps(_RECORDS, "/r/service-a")[1])
    b = _cloud(_opps(_RECORDS, "/r/service-b")[1])
    for name in a:
        assert a[name].sigma["id"] == again[name].sigma["id"]
        assert a[name].sigma["id"] != b[name].sigma["id"]


def test_cloud_rules_validate_with_pysigma_when_installed() -> None:
    pytest.importorskip("sigma")
    import importlib
    import inspect
    import pkgutil

    import sigma.validators.core as core
    from sigma.collection import SigmaCollection
    from sigma.validation import SigmaValidator
    from sigma.validators.base import SigmaRuleValidator

    docs = [o.sigma for o in _cloud(_opps(_RECORDS)[1]).values()]
    collection = SigmaCollection.from_dicts(docs, collect_errors=True)
    assert [(r.title, e) for r in collection for e in r.errors] == []
    validators = []
    for info in pkgutil.iter_modules(core.__path__):
        module = importlib.import_module(f"sigma.validators.core.{info.name}")
        for name, cls in vars(module).items():
            if (inspect.isclass(cls) and issubclass(cls, SigmaRuleValidator) and not inspect.isabstract(cls)
                    and cls.__module__ == module.__name__ and name not in ("ATTACKTagValidator", "D3FENDTagValidator")):
                validators.append(cls)
    assert list(SigmaValidator(validators).validate_rules(collection)) == []
