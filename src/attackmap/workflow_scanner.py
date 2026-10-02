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

Trigger trust (#246): ``pull_request_target``, ``issue_comment`` and
``workflow_run`` run with a write-capable token and secrets in scope while
reacting to attacker-controlled input. Rules below raise severity on them.

- **workflow_run_artifact_poisoning** — a ``workflow_run`` workflow downloads
  the triggering run's artifacts (``download-artifact`` with ``run-id``,
  ``dawidd6/action-download-artifact``, ``gh run download``, github-script
  ``downloadArtifact``) or checks out its head, then executes it. High
  (CWE-829) when a later step runs code; medium otherwise.
- **issue_comment_pr_checkout** — an ``issue_comment`` ("/ok-to-test")
  workflow checks out the PR (``refs/pull/N/head``, ``gh pr checkout``). High.
- **github_script_injection** — an attacker-controlled context interpolated
  into ``actions/github-script``'s ``script:``, which is evaluated as
  JavaScript with the token in scope. High.
- **github_env_injection** — an attacker-controlled value written to
  ``$GITHUB_ENV`` / ``$GITHUB_PATH`` (or ``$GITHUB_OUTPUT``), directly or via an
  ``env:`` binding. A newline lets it set ``LD_PRELOAD``/``NODE_OPTIONS`` for
  every later step. High (medium for ``$GITHUB_OUTPUT``).
- **default_token_permissions** — no ``permissions:`` block at the top level
  and on some job, so the job gets the repo/org default token (read/write on
  older repos). Low (medium on an untrusted trigger).
- **oidc_on_untrusted_trigger** — ``id-token: write`` on a PR/comment/run
  triggered workflow: PR code can mint cloud credentials. High.
- **secrets_inherit** — ``secrets: inherit`` into a reusable workflow, handing
  it every secret instead of the ones it needs. Medium (high on untrusted).
- **checkout_persist_credentials** — ``actions/checkout`` on an untrusted
  trigger without ``persist-credentials: false`` before steps run code: the
  write token is left in ``.git/config`` for that code to read. Medium.
- **cache_poisoning_pr_target** — ``actions/cache`` (or a ``setup-*`` cache)
  in a ``pull_request_target`` job that ran PR code or keys the cache on PR
  values: the entry lands in the base branch's cache scope. High.
- **docker_action_unpinned** — ``uses: docker://img:tag`` (or a docker
  ``action.yml`` image) not pinned by ``@sha256:``. Medium.
- **curl_pipe_shell** — ``curl … | sh`` in a ``run:`` step. Medium.

Line numbers are best-effort (PyYAML's safe_load discards them): we locate a
representative line by searching the raw text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .safe_fs import is_contained, is_oversized, is_unsafe_link, walk_repo
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
    # workflow_run (#246): the triggering run's branch / commit are fork-chosen.
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.workflow_run.display_title",
)

# Expression references that indicate a checkout of untrusted PR head code.
_PR_HEAD_REFS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
)
# ... of the triggering run's head under `workflow_run` (#246).
_WORKFLOW_RUN_HEAD_REFS = (
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit",
    "github.event.workflow_run.pull_requests",
)
# Checkout refs that are *not* PR code even under issue_comment.
_SAFE_CHECKOUT_REFS = ("github.sha", "github.ref", "github.event.repository.default_branch")

# Triggers that run with a write-capable token / secrets while reacting to
# attacker-controlled input (#246).
_UNTRUSTED_TRIGGERS = frozenset({"pull_request_target", "issue_comment", "workflow_run"})

_ARTIFACT_ACTIONS_CROSS_RUN = ("dawidd6/action-download-artifact",)
_ARTIFACT_ACTION = "actions/download-artifact"
_GITHUB_SCRIPT_ACTION = "actions/github-script"
_CACHE_ACTIONS = ("actions/cache", "actions/cache/restore", "actions/cache/save")
_SETUP_ACTION_PREFIX = "actions/setup-"

# `git fetch origin pull/123/head`, `refs/pull/${{ … }}/merge`. Bounded so it
# stays linear on hostile input (#236).
_PULL_REF_RE = re.compile(r"pull/(?:\$\{\{[^}]{0,120}\}\}|[^\s/]{1,120})/(?:head|merge)\b")
# `$NAME` / `${NAME}` shell variable references.
_SHELL_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]{0,100})")
# `inputs.<name>` / `github.event.inputs.<name>` references.
_INPUT_REF_RE = re.compile(r"\binputs\.([A-Za-z0-9_-]{1,100})")
_ENV_FILES = {"GITHUB_ENV": "high", "GITHUB_PATH": "high", "GITHUB_OUTPUT": "medium"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node"}


_ACTION_FILENAMES = {"action.yml", "action.yaml"}
_ACTION_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "vendor", "dist", "build"}


@dataclass
class _Ctx:
    """Per-workflow facts every rule consults."""

    rel: str
    lines: list[str]
    triggers: set[str] = field(default_factory=set)
    # Extra injectable expression prefixes with their severity (composite
    # action / reusable-workflow `inputs.*`).
    input_severity: dict[str, str] = field(default_factory=dict)
    extra_contexts: tuple[str, ...] = ()

    @property
    def untrusted(self) -> set[str]:
        return self.triggers & _UNTRUSTED_TRIGGERS

    @property
    def pr_target(self) -> bool:
        return "pull_request_target" in self.triggers

    def issue(self, kind: str, line: int | None, context: str, evidence: str, severity: str) -> WorkflowIssue:
        return WorkflowIssue(
            kind=kind,  # type: ignore[arg-type]
            file=self.rel,
            line=line,
            context=context,
            evidence_text=evidence,
            severity=severity,  # type: ignore[arg-type]
        )


def _action_name(uses: str) -> str:
    return uses.split("@", 1)[0].strip().lower()


def _scan_action(data: dict, rel: str, lines: list[str]) -> list[WorkflowIssue]:
    """Composite action metadata (`action.yml`, #237). Its `inputs.*` come from
    the calling workflow and often carry PR titles/branch names, so `inputs.*`
    interpolated into a `run:` script is script injection, just like
    `github.event.*` in a workflow. Docker actions are checked for an
    unpinned `docker://` image (#246)."""
    runs = data.get("runs")
    if not isinstance(runs, dict):
        return []
    using = str(runs.get("using", "")).lower()
    ctx = _Ctx(rel=rel, lines=lines, extra_contexts=("inputs.",))
    if using == "docker":
        image = runs.get("image")
        if isinstance(image, str) and image.startswith("docker://") and "@sha256:" not in image:
            return [
                ctx.issue(
                    "docker_action_unpinned",
                    _line_for(lines, image) or _line_for(lines, "image:"),
                    "docker action image",
                    f"image: {image} (pin by @sha256: digest)",
                    "medium",
                )
            ]
        return []
    if using != "composite":
        return []
    steps = runs.get("steps")
    if not isinstance(steps, list):
        return []
    issues: list[WorkflowIssue] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_name = str(step.get("name") or step.get("id") or step.get("uses") or "step")
        where = f"composite action step '{step_name}'"
        issues.extend(_scan_step(step, where, ctx, env={}, state=_JobState()))
    return issues


def _load_yaml(path: Path, yaml):  # type: ignore[no-untyped-def]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(text)
    except (OSError, yaml.YAMLError):  # type: ignore[attr-defined]
        return None, None
    return (data, text) if isinstance(data, dict) else (None, None)


def scan_workflows(root: str | Path) -> list[WorkflowIssue]:
    """Scan `.github/workflows/*.yml` and composite-action `action.yml` files
    under `root` for CI security issues."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return []

    root_path = Path(root)
    issues: list[WorkflowIssue] = []
    for path in walk_repo(root_path, prune=lambda name: name in _ACTION_SKIP_DIRS):
        if path.name not in _ACTION_FILENAMES or is_oversized(path):
            continue
        data, text = _load_yaml(path, yaml)
        if data is not None:
            issues.extend(_scan_action(data, path.relative_to(root_path).as_posix(), text.splitlines()))

    workflows_dir = root_path / ".github" / "workflows"
    if not workflows_dir.is_dir() or not is_contained(root_path, workflows_dir):
        return issues

    for path in sorted(workflows_dir.iterdir()):
        if path.suffix.lower() not in {".yml", ".yaml"} or not path.is_file():
            continue
        if is_unsafe_link(root_path, path) or is_oversized(path):
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


def _raw_on(data: dict):  # type: ignore[no-untyped-def]
    raw = data.get("on")
    if raw is None:
        raw = data.get(True)
    return raw


def _norm_triggers(data: dict) -> set[str]:
    """The workflow's `on:` triggers as a set of event names.

    PyYAML parses the bare key ``on:`` as the boolean ``True`` (YAML 1.1), so we
    look under both keys. ``on`` may be a string, a list, or a mapping.
    """
    raw = _raw_on(data)
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(x) for x in raw}
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    return set()


def _input_severities(data: dict, triggers: set[str]) -> dict[str, str]:
    """`inputs.<name>` → severity for free-text inputs of a reusable
    (`workflow_call`, medium) or manually dispatched (`workflow_dispatch`,
    low) workflow. Typed inputs (boolean/number/choice/environment) can't
    carry shell metacharacters and are skipped."""
    raw = _raw_on(data)
    out: dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for trigger, severity in (("workflow_dispatch", "low"), ("workflow_call", "medium")):
        spec = raw.get(trigger)
        if trigger not in triggers or not isinstance(spec, dict):
            continue
        inputs = spec.get("inputs")
        if not isinstance(inputs, dict):
            continue
        for name, decl in inputs.items():
            kind = str(decl.get("type", "string")).lower() if isinstance(decl, dict) else "string"
            if kind == "string" and out.get(str(name)) != "medium":
                out[str(name)] = severity
    return out


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


def _grants_id_token(permissions) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(permissions, dict):
        return str(permissions.get("id-token", "")).strip().lower() == "write"
    return _is_write_all(permissions)


def _env_map(*blocks) -> dict[str, str]:  # type: ignore[no-untyped-def]
    out: dict[str, str] = {}
    for block in blocks:
        if isinstance(block, dict):
            out.update({str(k): str(v) for k, v in block.items()})
    return out


def _injectable(expr: str, ctx: _Ctx) -> tuple[str, str] | None:
    """`(matched context, severity)` when an expression is attacker-controlled."""
    expr_flat = re.sub(r"\s+", "", expr)
    for c in _INJECTABLE_CONTEXTS + ctx.extra_contexts:
        if c in expr_flat:
            return c, "high"
    for m in _INPUT_REF_RE.finditer(expr_flat):
        severity = ctx.input_severity.get(m.group(1))
        if severity:
            return m.group(0), severity
    return None


def _first_injection(text: str, ctx: _Ctx) -> tuple[str, str, str] | None:
    """`(expr, matched context, severity)` of the first injectable `${{ }}`."""
    for match in _EXPR_RE.finditer(text):
        hit = _injectable(match.group(1), ctx)
        if hit:
            return match.group(1), hit[0], hit[1]
    return None


@dataclass
class _JobState:
    """What earlier steps in the job did (rules that depend on step order)."""

    pr_code_checked_out: bool = False  # untrusted PR / run head is in the workspace
    artifact_download: tuple[int | None, str, str] | None = None  # (line, where, evidence)
    credential_checkout: tuple[int | None, str] | None = None  # checkout leaving the token behind
    reported_artifact: bool = False
    reported_credentials: bool = False


def _scan_one(data: dict, rel: str, lines: list[str]) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    triggers = _norm_triggers(data)
    ctx = _Ctx(rel=rel, lines=lines, triggers=triggers, input_severity=_input_severities(data, triggers))
    untrusted = ctx.untrusted
    pr_trigger = bool(triggers & {"pull_request", "pull_request_target"})
    pr_target = ctx.pr_target
    trigger_label = ", ".join(sorted(untrusted))

    top_perms = data.get("permissions")
    # Top-level broad permissions.
    if _is_write_all(top_perms):
        issues.append(
            ctx.issue(
                "broad_permissions",
                _line_for(lines, "permissions:"),
                "workflow (top-level permissions)",
                "permissions: write-all",
                "high" if untrusted else "medium",
            )
        )
    oidc_triggers = untrusted | (triggers & {"pull_request"})
    if oidc_triggers and _grants_id_token(top_perms):
        issues.append(_oidc_issue(ctx, "workflow (top-level permissions)", oidc_triggers))

    jobs = list(_iter_jobs(data))
    if "permissions" not in data and any("permissions" not in job for _, job in jobs):
        unscoped = [job_id for job_id, job in jobs if "permissions" not in job]
        issues.append(
            ctx.issue(
                "default_token_permissions",
                _line_for(lines, "jobs:"),
                f"job(s) {', '.join(repr(j) for j in unscoped[:5])} (no permissions: block)",
                "no top-level or job permissions: block — the GITHUB_TOKEN gets the repo/org default"
                + (f" on an untrusted trigger ({trigger_label})" if untrusted else ""),
                "medium" if untrusted else "low",
            )
        )

    workflow_env = data.get("env")
    for job_id, job in jobs:
        # Job-level broad permissions.
        if _is_write_all(job.get("permissions")):
            issues.append(
                ctx.issue(
                    "broad_permissions",
                    _line_for(lines, f"{job_id}:") or _line_for(lines, "permissions:"),
                    f"job '{job_id}' permissions",
                    "permissions: write-all",
                    "high" if untrusted else "medium",
                )
            )
        if oidc_triggers and isinstance(job.get("permissions"), dict) and _grants_id_token(job["permissions"]):
            issues.append(_oidc_issue(ctx, f"job '{job_id}' permissions", oidc_triggers))

        # Reusable-workflow call: pinning and `secrets: inherit`.
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            issues.extend(_check_pin(job_uses, f"job '{job_id}' (reusable workflow)", ctx))
            if str(job.get("secrets", "")).strip().lower() == "inherit":
                issues.append(
                    ctx.issue(
                        "secrets_inherit",
                        _line_for(lines, "secrets:", "inherit", contains_all=True),
                        f"job '{job_id}' calls {job_uses}",
                        f"secrets: inherit passes every repository secret to {job_uses}"
                        + (f" on an untrusted trigger ({trigger_label})" if untrusted else ""),
                        "high" if untrusted else "medium",
                    )
                )

        # Self-hosted runner on a PR trigger.
        if pr_trigger and any(v.lower() == "self-hosted" for v in _runs_on_values(job)):
            issues.append(
                ctx.issue(
                    "self_hosted_pr",
                    _line_for(lines, "runs-on", "self-hosted", contains_all=True)
                    or _line_for(lines, "self-hosted"),
                    f"job '{job_id}' (runs-on self-hosted, {'pull_request_target' if pr_target else 'pull_request'})",
                    "self-hosted runner reachable from pull-request code",
                    "high" if pr_target else "medium",
                )
            )

        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        state = _JobState()
        job_env = _env_map(workflow_env, job.get("env"))
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_name = str(step.get("name") or step.get("id") or step.get("uses") or "step")
            where = f"job '{job_id}' step '{step_name}'"
            issues.extend(_scan_step(step, where, ctx, env=job_env, state=state))
        if state.artifact_download and not state.reported_artifact:
            # Downloaded but never executed in this job: still untrusted data
            # (it may be consumed as config or uploaded on), so medium.
            line, dl_where, evidence = state.artifact_download
            issues.append(
                ctx.issue(
                    "workflow_run_artifact_poisoning",
                    line,
                    dl_where,
                    f"{evidence} — treat them as untrusted data",
                    "medium",
                )
            )
    return issues


def _oidc_issue(ctx: _Ctx, where: str, triggers: set[str]) -> WorkflowIssue:
    untrusted = triggers & _UNTRUSTED_TRIGGERS
    return ctx.issue(
        "oidc_on_untrusted_trigger",
        _line_for(ctx.lines, "id-token", "write", contains_all=True) or _line_for(ctx.lines, "permissions:"),
        where,
        f"id-token: write on a {', '.join(sorted(triggers))}-triggered workflow — PR code can mint cloud OIDC credentials",
        "high" if untrusted else "low",
    )


def _executes_code(step: dict) -> bool:
    """A step that runs workspace code: a `run:` script or a local action."""
    uses = step.get("uses")
    return isinstance(step.get("run"), str) or (isinstance(uses, str) and uses.startswith("./"))


def _scan_step(step: dict, where: str, ctx: _Ctx, *, env: dict[str, str], state: _JobState) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    step_env = _env_map(env, step.get("env"))
    with_ = step.get("with") if isinstance(step.get("with"), dict) else {}

    # Step-order rules: something earlier in the job put untrusted code /
    # a credential in the workspace, and this step executes code.
    if _executes_code(step):
        if state.artifact_download and not state.reported_artifact:
            line, dl_where, evidence = state.artifact_download
            state.reported_artifact = True
            issues.append(
                ctx.issue(
                    "workflow_run_artifact_poisoning",
                    line,
                    f"{dl_where} → executed by {where}",
                    f"{evidence}, then executes workspace code with the base repo's token/secrets",
                    "high",
                )
            )
        untrusted_code = state.pr_code_checked_out or state.artifact_download is not None
        if state.credential_checkout and untrusted_code and not state.reported_credentials:
            line, co_where = state.credential_checkout
            state.reported_credentials = True
            issues.append(
                ctx.issue(
                    "checkout_persist_credentials",
                    line,
                    co_where,
                    f"actions/checkout on {', '.join(sorted(ctx.untrusted))} without persist-credentials: false; "
                    f"later step {where} runs code that can read the token from .git/config",
                    "medium",
                )
            )

    uses = step.get("uses")
    if isinstance(uses, str):
        issues.extend(_check_uses(uses, step, with_, where, ctx, state))

    run = step.get("run")
    if isinstance(run, str):
        issues.extend(_check_run(run, where, ctx, step_env, state))
    return issues


def _check_pin(uses: str, where: str, ctx: _Ctx) -> list[WorkflowIssue]:
    if uses.startswith("docker://"):
        if "@sha256:" in uses:
            return []
        return [
            ctx.issue(
                "docker_action_unpinned",
                _line_for(ctx.lines, uses) or _line_for(ctx.lines, "docker://"),
                where,
                f"uses: {uses} (pin by @sha256: digest)",
                "medium",
            )
        ]
    # Local (`./…`) actions aren't tag-pinned refs.
    if "@" not in uses or uses.startswith("."):
        return []
    ref = uses.split("@", 1)[1].strip()
    if _SHA_RE.match(ref):
        return []
    return [
        ctx.issue(
            "unpinned_action",
            _line_for(ctx.lines, uses) or _line_for(ctx.lines, "uses:"),
            where,
            f"uses: {uses} (pin to a full commit SHA)",
            "low" if _SEMVER_TAG_RE.match(ref) else "medium",
        )
    ]


def _check_uses(
    uses: str, step: dict, with_: dict, where: str, ctx: _Ctx, state: _JobState
) -> list[WorkflowIssue]:
    issues = _check_pin(uses, where, ctx)
    name = _action_name(uses)
    lines = ctx.lines

    if name.endswith("actions/checkout"):
        ref_val = str(with_.get("ref", ""))
        repo_val = str(with_.get("repository", ""))
        target = f"{ref_val} {repo_val}"
        if ctx.pr_target and any(head in target for head in _PR_HEAD_REFS):
            state.pr_code_checked_out = True
            issues.append(
                ctx.issue(
                    "pr_target_checkout",
                    _line_for(lines, "ref:", "head", contains_all=True) or _line_for(lines, "actions/checkout"),
                    where,
                    f"pull_request_target checks out untrusted PR code: ref: {ref_val}",
                    "high",
                )
            )
        if "workflow_run" in ctx.triggers and any(head in target for head in _WORKFLOW_RUN_HEAD_REFS):
            state.pr_code_checked_out = True
            issues.append(
                ctx.issue(
                    "workflow_run_artifact_poisoning",
                    _line_for(lines, "workflow_run.head") or _line_for(lines, "actions/checkout"),
                    where,
                    f"workflow_run checks out the triggering run's untrusted head: ref: {ref_val}",
                    "high",
                )
            )
        if "issue_comment" in ctx.triggers and _issue_comment_pr_ref(ref_val):
            state.pr_code_checked_out = True
            issues.append(
                ctx.issue(
                    "issue_comment_pr_checkout",
                    _line_for(lines, "ref:", ref_val[:40]) if ref_val else _line_for(lines, "actions/checkout"),
                    where,
                    f"issue_comment workflow checks out pull-request code: ref: {ref_val}",
                    "high",
                )
            )
        persist = str(with_.get("persist-credentials", "true")).strip().lower()
        if ctx.untrusted and persist != "false" and state.credential_checkout is None:
            state.credential_checkout = (
                _line_for(lines, "actions/checkout"),
                where,
            )

    if "workflow_run" in ctx.triggers and state.artifact_download is None:
        cross_run = name in _ARTIFACT_ACTIONS_CROSS_RUN or (
            name == _ARTIFACT_ACTION and ("run-id" in with_ or "github-token" in with_)
        )
        script = str(with_.get("script", "")) if name == _GITHUB_SCRIPT_ACTION else ""
        if cross_run or "downloadArtifact" in script:
            state.artifact_download = (
                _line_for(lines, name.split("/", 1)[-1]) or _line_for(lines, uses),
                where,
                f"workflow_run downloads the triggering run's artifacts ({name})",
            )

    if name == _GITHUB_SCRIPT_ACTION:
        script = with_.get("script")
        hit = _first_injection(script, ctx) if isinstance(script, str) else None
        if hit:
            expr, matched, severity = hit
            issues.append(
                ctx.issue(
                    "github_script_injection",
                    _line_for(lines, expr) or _line_for(lines, matched) or _line_for(lines, "script:"),
                    where,
                    f"attacker-controlled ${{{{ {expr} }}}} interpolated into actions/github-script script: (evaluated as JavaScript)",
                    severity,
                )
            )

    is_cache = name in _CACHE_ACTIONS or (name.startswith(_SETUP_ACTION_PREFIX) and with_.get("cache"))
    if ctx.pr_target and is_cache:
        key_text = f"{with_.get('key', '')} {with_.get('restore-keys', '')}"
        pr_keyed = any(c in key_text for c in _PR_HEAD_REFS + ("github.event.pull_request",))
        if state.pr_code_checked_out or pr_keyed:
            reason = "after checking out PR code" if state.pr_code_checked_out else f"keyed on PR-controlled values ({key_text.strip()})"
            issues.append(
                ctx.issue(
                    "cache_poisoning_pr_target",
                    _line_for(lines, uses),
                    where,
                    f"{name} on pull_request_target {reason} — the entry is saved to the base branch's cache scope",
                    "high",
                )
            )
    return issues


def _issue_comment_pr_ref(ref_val: str) -> bool:
    """A checkout ref under issue_comment that resolves to PR code: any
    expression other than the base commit/ref, or a literal `refs/pull/…`."""
    if not ref_val.strip():
        return False
    if "refs/pull/" in ref_val or _PULL_REF_RE.search(ref_val):
        return True
    exprs = [m.group(1).strip() for m in _EXPR_RE.finditer(ref_val)]
    return bool(exprs) and not all(e in _SAFE_CHECKOUT_REFS for e in exprs)


def _check_run(
    run: str, where: str, ctx: _Ctx, env: dict[str, str], state: _JobState
) -> list[WorkflowIssue]:
    issues: list[WorkflowIssue] = []
    lines = ctx.lines
    untrusted = ctx.untrusted

    hit = _first_injection(run, ctx)
    if hit:
        expr, matched, severity = hit
        issues.append(
            ctx.issue(
                "script_injection",
                _line_for(lines, expr) or _line_for(lines, matched) or _line_for(lines, "run:"),
                where,
                f"attacker-controlled ${{{{ {expr} }}}} interpolated into run: script",
                severity,
            )
        )
    for match in _EXPR_RE.finditer(run):
        expr = match.group(1)
        if re.sub(r"\s+", "", expr).startswith("secrets."):
            issues.append(
                ctx.issue(
                    "secret_in_run",
                    _line_for(lines, "secrets.") or _line_for(lines, "run:"),
                    where,
                    f"${{{{ {expr} }}}} interpolated into run: script (pass via env: instead)",
                    "high" if untrusted else "medium",
                )
            )
            break

    # PR checkout from a shell step under an untrusted trigger.
    if untrusted and ("gh pr checkout" in run or _PULL_REF_RE.search(run)):
        state.pr_code_checked_out = True
        kind = (
            "pr_target_checkout" if ctx.pr_target
            else "issue_comment_pr_checkout" if "issue_comment" in untrusted
            else "workflow_run_artifact_poisoning"
        )
        issues.append(
            ctx.issue(
                kind,
                _line_for(lines, "gh pr checkout") or _line_for(lines, "pull/") or _line_for(lines, "run:"),
                where,
                f"run: step fetches/checks out pull-request code on {', '.join(sorted(untrusted))}",
                "high",
            )
        )
    if "workflow_run" in ctx.triggers and "gh run download" in run and state.artifact_download is None:
        state.artifact_download = (
            _line_for(lines, "gh run download"),
            where,
            "workflow_run downloads the triggering run's artifacts (gh run download)",
        )

    issues.extend(_check_env_file_writes(run, where, ctx, env))
    issues.extend(_check_curl_pipe(run, where, ctx))
    return issues


def _tainted_env_names(env: dict[str, str], ctx: _Ctx) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in env.items():
        hit = _first_injection(value, ctx)
        if hit:
            out[name] = hit[0]
    return out


def _check_env_file_writes(run: str, where: str, ctx: _Ctx, env: dict[str, str]) -> list[WorkflowIssue]:
    tainted: dict[str, str] | None = None
    for raw_line in run.splitlines():
        if ">>" not in raw_line:
            continue
        target = next((f for f in _ENV_FILES if f in raw_line.split(">>", 1)[1]), None)
        if target is None:
            continue
        source = raw_line.split(">>", 1)[0]
        hit = _first_injection(source, ctx)
        via = f"${{{{ {hit[0]} }}}}" if hit else None
        if via is None:
            if tainted is None:
                tainted = _tainted_env_names(env, ctx)
            for m in _SHELL_VAR_RE.finditer(source):
                if m.group(1) in tainted:
                    via = f"${m.group(1)} (env: ${{{{ {tainted[m.group(1)]} }}}})"
                    break
        if via is None:
            continue
        return [
            ctx.issue(
                "github_env_injection",
                _line_for(ctx.lines, target, ">>", contains_all=True) or _line_for(ctx.lines, "run:"),
                where,
                f"attacker-controlled {via} written to ${target} — a newline sets arbitrary variables for later steps",
                _ENV_FILES[target],
            )
        ]
    return []


def _check_curl_pipe(run: str, where: str, ctx: _Ctx) -> list[WorkflowIssue]:
    for raw_line in run.splitlines():
        if "|" not in raw_line or ("curl" not in raw_line and "wget" not in raw_line):
            continue
        head, *tails = raw_line.split("|")
        if "curl" not in head and "wget" not in head:
            continue
        for tail in tails:
            words = tail.split()
            while words and words[0] in {"sudo", "-E", "env"}:
                words = words[1:]
            if words and words[0].rsplit("/", 1)[-1] in _SHELLS:
                return [
                    ctx.issue(
                        "curl_pipe_shell",
                        _line_for(ctx.lines, raw_line.strip()[:60]) or _line_for(ctx.lines, "run:"),
                        where,
                        f"remote script piped into a shell: {raw_line.strip()[:160]}",
                        "medium",
                    )
                ]
    return []
