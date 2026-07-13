"""Tests for the GitHub Actions / CI workflow security scanner (#142)."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzers import analyze_repository
from attackmap.recon_to_analysis import translate_recon
from attackmap.workflow_scanner import scan_workflows


def _repo(tmp_path: Path, yaml_text: str, name: str = "ci.yml") -> Path:
    wdir = tmp_path / ".github" / "workflows"
    wdir.mkdir(parents=True, exist_ok=True)
    (wdir / name).write_text(yaml_text, encoding="utf-8")
    return tmp_path


def _kinds(tmp_path: Path) -> list[str]:
    return [i.kind for i in scan_workflows(tmp_path)]


# ---------------------------------------------------------------------------
# Per-pattern detection
# ---------------------------------------------------------------------------


def test_unpinned_action_branch_is_medium(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@main
""",
    )
    issues = scan_workflows(repo)
    assert [i.kind for i in issues] == ["unpinned_action"]
    assert issues[0].severity == "medium"


def test_unpinned_action_semver_tag_is_low(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
    )
    issues = scan_workflows(repo)
    assert [i.kind for i in issues] == ["unpinned_action"]
    assert issues[0].severity == "low"


def test_sha_pinned_action_is_clean(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
""",
    )
    assert _kinds(repo) == []


def test_local_and_docker_actions_are_not_flagged(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.19
""",
    )
    assert _kinds(repo) == []


def test_pr_target_checkout_of_head_ref_is_high(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [pull_request_target]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""",
    )
    issues = scan_workflows(repo)
    kinds = {i.kind for i in issues}
    assert "pr_target_checkout" in kinds
    pr = next(i for i in issues if i.kind == "pr_target_checkout")
    assert pr.severity == "high"


def test_pull_request_target_without_head_checkout_is_clean(tmp_path: Path) -> None:
    # Checking out the base ref under pull_request_target is the safe pattern.
    repo = _repo(
        tmp_path,
        """
on: [pull_request_target]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
""",
    )
    assert "pr_target_checkout" not in _kinds(repo)


def test_secret_in_run(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          deploy --token ${{ secrets.DEPLOY_TOKEN }}
""",
    )
    assert "secret_in_run" in _kinds(repo)


def test_secret_via_env_is_clean(tmp_path: Path) -> None:
    # The recommended pattern: secret bound to env, referenced as a shell var.
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: |
          deploy --token "$TOKEN"
""",
    )
    assert "secret_in_run" not in _kinds(repo)


def test_script_injection_via_issue_title(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [issues]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.issue.title }}"
""",
    )
    issues = scan_workflows(repo)
    inj = [i for i in issues if i.kind == "script_injection"]
    assert len(inj) == 1
    assert inj[0].severity == "high"


def test_script_injection_head_ref(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [pull_request]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          git checkout ${{ github.head_ref }}
""",
    )
    assert "script_injection" in _kinds(repo)


def test_safe_context_in_run_is_clean(tmp_path: Path) -> None:
    # github.sha / github.repository are not attacker-controlled.
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "building ${{ github.sha }} in ${{ github.repository }}"
""",
    )
    assert "script_injection" not in _kinds(repo)


def test_broad_permissions_top_level_and_job(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
permissions: write-all
jobs:
  b:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
""",
    )
    broad = [i for i in scan_workflows(repo) if i.kind == "broad_permissions"]
    assert len(broad) == 2
    assert {i.context for i in broad} == {
        "workflow (top-level permissions)",
        "job 'b' permissions",
    }


def test_scoped_permissions_are_clean(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""",
    )
    assert "broad_permissions" not in _kinds(repo)


def test_self_hosted_on_pr_target_is_high(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [pull_request_target]
jobs:
  b:
    runs-on: self-hosted
    steps:
      - run: echo hi
""",
    )
    issues = [i for i in scan_workflows(repo) if i.kind == "self_hosted_pr"]
    assert len(issues) == 1
    assert issues[0].severity == "high"


def test_self_hosted_without_pr_trigger_is_clean(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: self-hosted
    steps:
      - run: echo hi
""",
    )
    assert "self_hosted_pr" not in _kinds(repo)


# ---------------------------------------------------------------------------
# Hardened workflow — the "clean produces nothing" acceptance criterion
# ---------------------------------------------------------------------------


def test_hardened_workflow_is_clean(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        """
name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: build
        env:
          TOKEN: ${{ secrets.CI_TOKEN }}
        run: |
          echo "building ${{ github.sha }}"
          deploy --token "$TOKEN"
""",
    )
    assert scan_workflows(repo) == []


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_on_boolean_key_gotcha_is_handled(tmp_path: Path) -> None:
    # PyYAML parses bare `on:` as the boolean True; triggers must still resolve.
    repo = _repo(
        tmp_path,
        """
on:
  pull_request_target:
jobs:
  b:
    runs-on: self-hosted
    steps:
      - run: echo hi
""",
    )
    assert "self_hosted_pr" in _kinds(repo)


def test_invalid_yaml_is_skipped(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "this: : : not valid yaml\n  - [")
    assert scan_workflows(repo) == []


def test_no_workflows_dir_is_empty(tmp_path: Path) -> None:
    assert scan_workflows(tmp_path) == []


def test_yaml_extension_variant(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        "on: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: x/y@main\n",
        name="release.yaml",
    )
    assert _kinds(repo) == ["unpinned_action"]


# ---------------------------------------------------------------------------
# Finding synthesis + pipeline integration
# ---------------------------------------------------------------------------


def test_findings_synthesized_through_analyze_repository(tmp_path: Path) -> None:
    _repo(
        tmp_path,
        """
on: [pull_request_target]
permissions: write-all
jobs:
  b:
    runs-on: self-hosted
    steps:
      - uses: some/action@main
      - run: |
          echo "${{ github.event.issue.title }}"
""",
    )
    scan = analyze_repository(tmp_path)
    # The merge must carry workflow_issues through the analyzer pipeline.
    assert scan.workflow_issues, "workflow_issues dropped by the analyzer merge"
    findings = [
        f for f in translate_recon(scan).findings if "ci-security" in f.tags
    ]
    titles = {f.title for f in findings}
    assert any("script injection" in t.lower() for t in titles)
    assert any("write-all" in t.lower() for t in titles)
    # ci-security findings carry the supply-chain tag and an ATT&CK technique.
    for f in findings:
        assert "supply-chain" in f.tags
        assert f.attack_techniques


def test_finding_severity_is_max_over_kind(tmp_path: Path) -> None:
    # Two unpinned actions: one semver (low), one branch (medium) → medium finding.
    _repo(
        tmp_path,
        """
on: [push]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some/action@main
""",
    )
    scan = analyze_repository(tmp_path)
    findings = [
        f
        for f in translate_recon(scan).findings
        if f.title.startswith("Unpinned GitHub Action")
    ]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
