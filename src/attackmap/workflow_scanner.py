"""GitHub Actions / CI workflow security scanner (#142).

CI config is a real attack surface that AttackMap otherwise leaves
unanalyzed: `.github/workflows/*.yml` routinely carry supply-chain and
code-execution risks. This built-in pass parses each workflow at the repo
root's `.github/workflows/` and emits a `WorkflowIssue` per positively-present
misconfiguration. A hardened workflow produces nothing.

Detected patterns:

- **unpinned_action** — `uses: org/action@<tag-or-branch>` instead of a pinned
  commit SHA. A moved tag / branch lets the action's owner (or anyone who
  compromises them) change what runs in your pipeline. Semver tags are low;
  branch/`latest` refs are medium.
- **pr_target_checkout** — `on: pull_request_target` combined with a checkout of
  the PR head ref. `pull_request_target` runs with the base repo's secrets in
  scope, so checking out and building untrusted PR code is a classic
  confused-deputy that leaks secrets / achieves RCE. High.
- **secret_in_run** — `${{ secrets.* }}` interpolated straight into a `run:`
  shell step, where it can leak via logs, `ps`, or a child process. Pass secrets
  through `env:` instead. Medium.
- **script_injection** — an attacker-controlled context
  (`github.event.*.{title,body,…}`, `github.head_ref`, …) interpolated into a
  `run:` block, so a crafted issue/PR title runs arbitrary shell. High.
- **broad_permissions** — `permissions: write-all` (or the `write` shorthand),
  granting the `GITHUB_TOKEN` far more than a job needs. Medium.
- **self_hosted_pr** — a self-hosted runner on a `pull_request` /
  `pull_request_target` trigger, exposing your runner to arbitrary code from
  forks on a public repo. Medium (high with `pull_request_target`).

Line numbers are best-effort (PyYAML's safe_load discards them): we locate a
representative line by searching the raw text.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import WorkflowIssue

# A pinned action ref is a full 40-hex commit SHA. Anything else is "unpinned".
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# A semver-ish tag (`v4`, `v4.1.0`, `1.2.3`) — unpinned but lower risk than a
# branch ref like `main` / `master` / `latest`.
_SEMVER_TAG_RE = re.compile(r"^v?\d+(?:\.\d+)*$")

# `${{ <expr> }}` interpolation.
_EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)

# Attacker-controlled expression contexts that are dangerous inside a `run:`
# shell step (GitHub's own "untrusted input" list). Matched as substrings of
# the expression text.
_INJECTABLE_CONTEXTS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits",  # .*.message / .author.*
    "github.event.pages",  # .*.page_name
    "github.head_ref",
)

# Expression references that indicate a checkout of untrusted PR head code.
_PR_HEAD_REFS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
)


def scan_workflows(root: str | Path) -> list[WorkflowIssue]:
    """Scan `.github/workflows/*.yml` under `root` for CI security issues."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return []

    root_path = Path(root)
    workflows_dir = root_path / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return []

    issues: list[WorkflowIssue] = []
    for path in sorted(workflows_dir.iterdir()):
        if path.suffix.lower() not in {".yml", ".yaml"} or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:  # type: ignore[attr-defined]
            continue
        if not isinstance(data, dict):
            continue
        rel = str(path.relative_to(root_path))
        lines = text.splitlines()
        issues.extend(_scan_one(data, rel, lines))
    return issues


def _norm_triggers(data: dict) -> set[str]:
    """The workflow's `on:` triggers as a set of event names.

    PyYAML parses the bare key ``on:`` as the boolean ``True`` (YAML 1.1), so we
    look under both keys. ``on`` may be a string, a list, or a mapping.
    """
    raw = data.get("on")
    if raw is None:
        raw = data.get(True)
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(x) for x in raw}
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    return set()


def _line_for(lines: list[str], *needles: str, contains_all: bool = False) -> int | None:
    """Best-effort 1-based line number of the first line matching needle(s)."""
    for idx, line in enumerate(lines, start=1):
        if contains_all:
            if all(n in line for n in needles):
                return idx
        elif any(n in line for n in needles):
            return idx
    return None


def _iter_jobs(data: dict):
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if isinstance(job, dict):
            yield str(job_id), job


def _runs_on_values(job: dict) -> list[str]:
    raw = job.get("runs-on")
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, dict):  # runs-on: { group: …, labels: [...] }
        labels = raw.get("labels")
        if isinstance(labels, str):
            return [labels]
        if isinstance(labels, list):
            return [str(x) for x in labels]
    return []


def _is_write_all(permissions) -> bool:
    """True when a `permissions:` value grants blanket write access."""
    if isinstance(permissions, str):
        return permissions.strip().lower() in {"write-all", "write"}
    return False


def _scan_one(data: dict, rel: str, lines: list[str]) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    triggers = _norm_triggers(data)
    pr_trigger = bool(triggers & {"pull_request", "pull_request_target"})
    pr_target = "pull_request_target" in triggers

    # Top-level broad permissions.
    if _is_write_all(data.get("permissions")):
        issues.append(
            WorkflowIssue(
                kind="broad_permissions",
                file=rel,
                line=_line_for(lines, "permissions:"),
                context="workflow (top-level permissions)",
                evidence_text="permissions: write-all",
                severity="medium",
            )
        )

    for job_id, job in _iter_jobs(data):
        # Job-level broad permissions.
        if _is_write_all(job.get("permissions")):
            issues.append(
                WorkflowIssue(
                    kind="broad_permissions",
                    file=rel,
                    line=_line_for(lines, f"{job_id}:") or _line_for(lines, "permissions:"),
                    context=f"job '{job_id}' permissions",
                    evidence_text="permissions: write-all",
                    severity="medium",
                )
            )

        # Self-hosted runner on a PR trigger.
        if pr_trigger and any(v.lower() == "self-hosted" for v in _runs_on_values(job)):
            issues.append(
                WorkflowIssue(
                    kind="self_hosted_pr",
                    file=rel,
                    line=_line_for(lines, "runs-on", "self-hosted", contains_all=True)
                    or _line_for(lines, "self-hosted"),
                    context=f"job '{job_id}' (runs-on self-hosted, {'pull_request_target' if pr_target else 'pull_request'})",
                    evidence_text="self-hosted runner reachable from pull-request code",
                    severity="high" if pr_target else "medium",
                )
            )

        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            issues.extend(_scan_step(step, job_id, rel, lines, pr_target=pr_target))
    return issues


def _scan_step(
    step: dict, job_id: str, rel: str, lines: list[str], *, pr_target: bool
) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    step_name = str(step.get("name") or step.get("id") or step.get("uses") or "step")
    ctx = f"job '{job_id}' step '{step_name}'"

    uses = step.get("uses")
    if isinstance(uses, str):
        issue = _check_uses(uses, step, ctx, rel, lines, pr_target=pr_target)
        issues.extend(issue)

    run = step.get("run")
    if isinstance(run, str):
        issues.extend(_check_run(run, ctx, rel, lines))

    return issues


def _check_uses(
    uses: str, step: dict, ctx: str, rel: str, lines: list[str], *, pr_target: bool
) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    # Local (`./…`) and docker (`docker://…`) actions aren't tag-pinned refs.
    is_remote = "@" in uses and not uses.startswith((".", "docker://"))

    if is_remote:
        ref = uses.split("@", 1)[1].strip()
        if not _SHA_RE.match(ref):
            severity = "low" if _SEMVER_TAG_RE.match(ref) else "medium"
            issues.append(
                WorkflowIssue(
                    kind="unpinned_action",
                    file=rel,
                    line=_line_for(lines, uses) or _line_for(lines, f"uses:"),
                    context=ctx,
                    evidence_text=f"uses: {uses} (pin to a full commit SHA)",
                    severity=severity,
                )
            )

    # pull_request_target checkout of the PR head ref.
    if pr_target and uses.split("@", 1)[0].endswith("actions/checkout"):
        with_ = step.get("with")
        ref_val = str(with_.get("ref", "")) if isinstance(with_, dict) else ""
        if any(head in ref_val for head in _PR_HEAD_REFS):
            issues.append(
                WorkflowIssue(
                    kind="pr_target_checkout",
                    file=rel,
                    line=_line_for(lines, "ref:", "head", contains_all=True)
                    or _line_for(lines, "actions/checkout"),
                    context=ctx,
                    evidence_text=f"pull_request_target checks out untrusted PR code: ref: {ref_val}",
                    severity="high",
                )
            )
    return issues


def _check_run(run: str, ctx: str, rel: str, lines: list[str]) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    seen_injection = False
    seen_secret = False
    for match in _EXPR_RE.finditer(run):
        expr = match.group(1)
        expr_flat = re.sub(r"\s+", "", expr)
        matched_ctx = next(
            (c for c in _INJECTABLE_CONTEXTS if re.sub(r"\s+", "", c) in expr_flat), None
        )
        if not seen_injection and matched_ctx is not None:
            seen_injection = True
            issues.append(
                WorkflowIssue(
                    kind="script_injection",
                    file=rel,
                    line=_line_for(lines, matched_ctx) or _line_for(lines, "run:"),
                    context=ctx,
                    evidence_text=f"attacker-controlled ${{{{ {expr} }}}} interpolated into run: script",
                    severity="high",
                )
            )
        if not seen_secret and expr_flat.startswith("secrets."):
            seen_secret = True
            issues.append(
                WorkflowIssue(
                    kind="secret_in_run",
                    file=rel,
                    line=_line_for(lines, "secrets.") or _line_for(lines, "run:"),
                    context=ctx,
                    evidence_text=f"${{{{ {expr} }}}} interpolated into run: script (pass via env: instead)",
                    severity="medium",
                )
            )
    return issues
