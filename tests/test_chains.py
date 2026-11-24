from pathlib import Path

from attackmap.chains import build_attack_chains, evidence_id
from attackmap.models import Finding, FindingLocation
from attackmap.sarif import build_sarif
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings

_PR_TARGET = """name: pr
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
      - run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}
"""
_PUSH_RELEASE = """name: release
on: push
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: ./publish.sh ${{ secrets.NPM_TOKEN }}
"""


def _workflow_findings(tmp_path: Path, **files: str) -> list[Finding]:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    for name, text in files.items():
        (wf / f"{name}.yml").write_text(text)
    return generate_findings(scan_repo(tmp_path))


def _finding(rule: str, file: str, line: int, confidence: str = "high") -> Finding:
    return Finding(
        title=rule, rule_id=rule, severity="high", mitigation="-", confidence=confidence,
        locations=[FindingLocation(file=file, line=line)],
    )


def _chain(chains, impact):
    return next((c for c in chains if c.impact == impact), None)


def test_pr_target_checkout_and_deploy_secret_chain_to_secrets(tmp_path: Path) -> None:
    findings = _workflow_findings(tmp_path, pr=_PR_TARGET)
    chain = _chain(build_attack_chains(findings), "secrets")
    assert chain is not None and chain.start == ["fork_pr"]
    assert [s.rule_id for s in chain.steps] == ["pr-target-checkout", "secret-in-run"]
    # Every evidence id resolves to a real finding location.
    real = {evidence_id(f.rule_id, loc) for f in findings for loc in f.locations}
    assert all(e in real for s in chain.steps for e in s.evidence_ids)


def test_removing_any_enabling_finding_removes_the_chain(tmp_path: Path) -> None:
    findings = _workflow_findings(tmp_path, pr=_PR_TARGET)
    chain = _chain(build_attack_chains(findings), "secrets")
    for step in chain.steps:
        rest = [f for f in findings if f.rule_id != step.rule_id]
        assert _chain(build_attack_chains(rest), "secrets") is None, step.rule_id


def test_ci_code_exec_does_not_reach_another_workflows_secrets(tmp_path: Path) -> None:
    pr_without_secret = _PR_TARGET.replace(" --token ${{ secrets.DEPLOY_TOKEN }}", "")
    findings = _workflow_findings(tmp_path, pr=pr_without_secret, release=_PUSH_RELEASE)
    assert "secret-in-run" in {f.rule_id for f in findings}
    assert _chain(build_attack_chains(findings), "secrets") is None


def test_findings_compose_across_classes_into_cluster_admin() -> None:
    findings = [
        _finding("ssti", "app/views.py", 12),
        _finding("cluster-admin-binding", "k8s/rbac.yaml", 3, "medium"),
    ]
    chain = _chain(build_attack_chains(findings), "cluster_admin")
    assert [s.rule_id for s in chain.steps] == ["ssti", "cluster-admin-binding"]
    assert chain.likelihood == 0.48 and chain.steps[1].precondition_notes
    # A single finding is not a chain.
    assert build_attack_chains(findings[:1]) == []


def test_sarif_puts_the_chain_on_its_final_steps_result() -> None:
    findings = [_finding("ssti", "app/views.py", 12), _finding("cluster-admin-binding", "k8s/rbac.yaml", 3)]
    chains = build_attack_chains(findings)
    results = build_sarif(findings, attack_chains=chains)["runs"][0]["results"]
    [final] = [r for r in results if r["ruleId"] == "cluster-admin-binding"]
    flow_uris = [
        loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
        for loc in final["codeFlows"][0]["threadFlows"][0]["locations"]
    ]
    assert flow_uris == ["app/views.py", "k8s/rbac.yaml"]


def test_step_library_names_only_real_rules() -> None:
    from attackmap.chains import STEP_LIBRARY
    from attackmap.threat_model import rule_catalog

    assert set(STEP_LIBRARY) <= {rule for rule, _, _ in rule_catalog()}
