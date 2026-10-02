"""CI workflow scanner gap rules (#246): one fixture per rule under
`tests/fixtures/workflows/<rule>/`, each with a hardened negative twin."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from attackmap.recon_to_analysis import translate_recon
from attackmap.scanner import scan_repo
from attackmap.threat_model import rule_catalog
from attackmap.workflow_scanner import scan_workflows

FIXTURES = Path(__file__).parent / "fixtures" / "workflows"
RULES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())
NEW_RULES = {
    "workflow_run_artifact_poisoning",
    "issue_comment_pr_checkout",
    "github_script_injection",
    "github_env_injection",
    "default_token_permissions",
    "oidc_on_untrusted_trigger",
    "secrets_inherit",
    "checkout_persist_credentials",
    "cache_poisoning_pr_target",
    "docker_action_unpinned",
    "curl_pipe_shell",
}
# Hardened twins that still carry an unrelated, intended issue (the persist-
# credentials twin still checks out PR code on pull_request_target).
NOT_FULLY_CLEAN = {"checkout_persist_credentials"}


def _install(tmp_path: Path, src: Path, name: str = "ci.yml") -> Path:
    wdir = tmp_path / ".github" / "workflows"
    wdir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, wdir / name)
    return tmp_path


def _workflow(tmp_path: Path, text: str) -> list:
    wdir = tmp_path / ".github" / "workflows"
    wdir.mkdir(parents=True, exist_ok=True)
    (wdir / "ci.yml").write_text(text, encoding="utf-8")
    return scan_workflows(tmp_path)


def test_every_new_rule_has_a_fixture_pair() -> None:
    assert NEW_RULES <= set(RULES)
    for rule in RULES:
        assert (FIXTURES / rule / "vulnerable.yml").is_file()
        assert (FIXTURES / rule / "hardened.yml").is_file()


@pytest.mark.parametrize("rule", RULES)
def test_vulnerable_fixture_fires(tmp_path: Path, rule: str) -> None:
    issues = scan_workflows(_install(tmp_path, FIXTURES / rule / "vulnerable.yml"))
    assert rule in {i.kind for i in issues}, [i.kind for i in issues]


@pytest.mark.parametrize("rule", RULES)
def test_hardened_twin_is_clean(tmp_path: Path, rule: str) -> None:
    issues = scan_workflows(_install(tmp_path, FIXTURES / rule / "hardened.yml"))
    assert rule not in {i.kind for i in issues}
    if rule not in NOT_FULLY_CLEAN:
        assert issues == [], [(i.kind, i.evidence_text) for i in issues]


@pytest.mark.parametrize("rule", sorted(NEW_RULES))
def test_new_rules_are_catalogued(rule: str) -> None:
    assert rule.replace("_", "-") in {r for r, _, _ in rule_catalog()}


def test_workflow_run_artifact_execution_is_high_cwe_829(tmp_path: Path) -> None:
    repo = _install(tmp_path, FIXTURES / "workflow_run_artifact_poisoning" / "vulnerable.yml")
    issues = [i for i in scan_workflows(repo) if i.kind == "workflow_run_artifact_poisoning"]
    assert [i.severity for i in issues] == ["high"]
    finding = next(
        f for f in translate_recon(scan_repo(repo)).findings
        if f.rule_id == "workflow-run-artifact-poisoning"
    )
    assert finding.severity == "high"
    assert "external/cwe/cwe-829" in finding.tags


def test_workflow_run_download_without_execution_is_medium(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on:
  workflow_run:
    workflows: [build]
    types: [completed]
permissions: {}
jobs:
  r:
    runs-on: ubuntu-latest
    steps:
      - uses: dawidd6/action-download-artifact@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          name: coverage
""")
    assert [(i.kind, i.severity) for i in issues] == [("workflow_run_artifact_poisoning", "medium")]


def test_same_run_download_artifact_is_not_poisoning(tmp_path: Path) -> None:
    # Without run-id, download-artifact reads the *current* run's artifacts.
    issues = _workflow(tmp_path, """
on:
  workflow_run:
    workflows: [build]
    types: [completed]
permissions: {}
jobs:
  r:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - run: ls
""")
    assert issues == []


def test_workflow_run_head_checkout_and_github_script_download(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on:
  workflow_run:
    workflows: [build]
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
          persist-credentials: false
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          script: |
            await github.rest.actions.downloadArtifact({owner, repo, artifact_id: id, archive_format: 'zip'})
      - run: unzip pr.zip && bash pr/run.sh
""")
    hits = [i for i in issues if i.kind == "workflow_run_artifact_poisoning"]
    assert len(hits) == 2 and {i.severity for i in hits} == {"high"}


def test_issue_comment_gh_pr_checkout_in_run(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: issue_comment
permissions: {}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout ${{ github.event.issue.number }} && make test
""")
    assert "issue_comment_pr_checkout" in {i.kind for i in issues}


def test_issue_comment_checkout_of_step_output_ref(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: issue_comment
permissions: {}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ steps.pr.outputs.head_sha }}
          persist-credentials: false
""")
    assert [i.kind for i in issues] == ["issue_comment_pr_checkout"]


def test_issue_comment_checkout_of_base_is_clean(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: issue_comment
permissions: {}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.sha }}
          persist-credentials: false
""")
    assert issues == []


def test_git_fetch_pull_head_on_pr_target(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: pull_request_target
permissions: {}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: |
          git fetch origin pull/${{ github.event.number }}/head:pr
          git checkout pr && make
""")
    assert "pr_target_checkout" in {i.kind for i in issues}


def test_untrusted_trigger_raises_secret_and_permission_severity(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: pull_request_target
permissions: write-all
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: deploy --token ${{ secrets.TOKEN }}
""")
    sev = {i.kind: i.severity for i in issues}
    assert sev["broad_permissions"] == "high"
    assert sev["secret_in_run"] == "high"
    assert sev["oidc_on_untrusted_trigger"] == "high"  # write-all includes id-token


def test_default_permissions_is_medium_on_untrusted_trigger(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, "on: issue_comment\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: echo\n")
    assert [(i.kind, i.severity) for i in issues] == [("default_token_permissions", "medium")]


def test_default_permissions_satisfied_by_every_job(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: push
jobs:
  a:
    runs-on: x
    permissions: {contents: read}
    steps: [{run: echo}]
  b:
    runs-on: x
    permissions: {contents: read}
    steps: [{run: echo}]
""")
    assert issues == []


def test_oidc_on_pull_request_is_low(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: pull_request
permissions:
  id-token: write
jobs:
  t:
    runs-on: x
    steps: [{run: echo}]
""")
    assert [(i.kind, i.severity) for i in issues] == [("oidc_on_untrusted_trigger", "low")]


def test_reusable_workflow_job_is_pin_checked(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: push
permissions: {}
jobs:
  r:
    uses: org/shared/.github/workflows/release.yml@main
""")
    assert [i.kind for i in issues] == ["unpinned_action"]


def test_github_env_direct_expression_and_output_severity(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: issues
permissions: {}
jobs:
  t:
    runs-on: x
    steps:
      - run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
""")
    env = [i for i in issues if i.kind == "github_env_injection"]
    assert [i.severity for i in env] == ["medium"]


def test_cache_after_pr_checkout_on_pr_target(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: pull_request_target
permissions: {}
jobs:
  t:
    runs-on: x
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - uses: actions/setup-node@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          cache: npm
""")
    assert "cache_poisoning_pr_target" in {i.kind for i in issues}


def test_cache_on_pr_target_without_pr_code_is_clean(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: pull_request_target
permissions: {}
jobs:
  t:
    runs-on: x
    steps:
      - uses: actions/setup-node@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          cache: npm
""")
    assert issues == []


def test_persist_credentials_needs_untrusted_code(tmp_path: Path) -> None:
    # Base checkout on pull_request_target running base code: no PR code runs.
    issues = _workflow(tmp_path, """
on: pull_request_target
permissions: {}
jobs:
  t:
    runs-on: x
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - run: ./scripts/label.sh
""")
    assert issues == []


def test_workflow_call_string_input_is_medium_and_typed_input_clean(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on:
  workflow_call:
    inputs:
      title: {type: string}
      dry: {type: boolean}
permissions: {}
jobs:
  t:
    runs-on: x
    steps:
      - run: echo "${{ inputs.dry }}"
      - run: echo "${{ inputs.title }}"
""")
    assert [(i.kind, i.severity) for i in issues] == [("script_injection", "medium")]


def test_curl_pipe_variants(tmp_path: Path) -> None:
    issues = _workflow(tmp_path, """
on: push
permissions: {}
jobs:
  t:
    runs-on: x
    steps:
      - run: wget -qO- https://get.example.sh | sh -s -- -y
      - run: curl -s https://api.example.com | jq .
""")
    assert [i.kind for i in issues] == ["curl_pipe_shell"]


def test_scanner_runs_on_action_yml(tmp_path: Path) -> None:
    (tmp_path / "act").mkdir()
    (tmp_path / "act" / "action.yml").write_text("""
runs:
  using: composite
  steps:
    - shell: bash
      run: curl -fsSL https://x.example/install | bash
    - uses: actions/github-script@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      with:
        script: core.info("${{ inputs.title }}")
""", encoding="utf-8")
    (tmp_path / "docker-act").mkdir()
    (tmp_path / "docker-act" / "action.yaml").write_text(
        "runs:\n  using: docker\n  image: docker://ghcr.io/org/tool:1\n", encoding="utf-8"
    )
    kinds = sorted(i.kind for i in scan_workflows(tmp_path))
    assert kinds == ["curl_pipe_shell", "docker_action_unpinned", "github_script_injection"]
