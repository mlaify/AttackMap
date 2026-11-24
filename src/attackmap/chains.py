"""Attack chains (#248): findings composed into precondition → postcondition chains.

Each finding whose rule is in `STEP_LIBRARY` becomes a step that *requires*
some attacker capabilities and *grants* others. The planner works backwards
from each goal capability to the attacker's start set, so every chain uses
only steps it needs, and every step cites the finding that enables it. No
step comes from a template: a rule with no finding contributes nothing.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import AttackChain, Capability, ChainStep, Finding, FindingLocation, finding_rule_id

# What an internet attacker has before any finding: network reach to public
# routes, and the ability to open a pull request from a fork.
START: frozenset[Capability] = frozenset({"net_access_public", "fork_pr"})

# A capability that implies others without a further step.
IMPLIES: dict[Capability, frozenset[Capability]] = {
    "code_exec_app": frozenset({"read_fs"}),
    "authn_admin": frozenset({"authn_user"}),
}

GOALS: tuple[Capability, ...] = (
    "cloud_admin", "cluster_admin", "cloud_creds", "node_root", "secrets", "ci_token",
    "db_write", "db_read", "authn_admin", "code_exec_app",
)

_NET = frozenset({"net_access_public"})
_FORK = frozenset({"fork_pr"})
_USER = frozenset({"authn_user"})
_EXEC = frozenset({"code_exec_app"})
_CI = frozenset({"ci_code_exec"})


def _rules(rules: str, requires: frozenset[Capability], grants: Iterable[Capability]) -> dict:
    return {rule: (requires, frozenset(grants)) for rule in rules.split()}


# rule id -> (requires, grants). Only rules whose finding alone justifies the
# transition; anything needing a signal core doesn't emit is left out rather
# than assumed.
STEP_LIBRARY: dict[str, tuple[frozenset[Capability], frozenset[Capability]]] = {
    # Forged or fixed credentials.
    **_rules("jwt-alg-confusion jwt-weak-secret jwt-unverified-decode jwt-header-trust "
             "session-weak-secret session-fixation", _NET, {"authn_user"}),
    # Authorization gaps once logged in.
    **_rules("bfla-privileged-route mass-assignment", _USER, {"authn_admin"}),
    **_rules("bola-modify", _USER, {"db_read", "db_write"}),
    **_rules("bola-read", _USER, {"db_read"}),
    # Injection from public routes.
    **_rules("sql-injection nosql-injection", _NET, {"db_read", "db_write"}),
    **_rules("code-injection eval exec subprocess-shell unsafe-deserialization ssti "
             "jndi-injection expression-injection", _NET, {"code_exec_app"}),
    **_rules("path-traversal xxe", _NET, {"read_fs"}),
    **_rules("ssrf", _NET, {"internal_network"}),
    # From the application's process or files.
    **_rules("hardcoded-secret", frozenset({"read_fs"}), {"secrets"}),
    **_rules("secret-env-reference", _EXEC, {"secrets"}),
    # Out of the container, into the cluster (assumes the exploited app runs
    # in that workload; stated on the step).
    **_rules("privileged-container host-path-mount host-namespace-shared dangerous-capability",
             _EXEC, {"node_root"}),
    **_rules("rbac-secret-access", _EXEC, {"secrets"}),
    **_rules("cluster-admin-binding rbac-wildcard rbac-escalation", _EXEC, {"cluster_admin"}),
    # CI: untrusted code in a privileged workflow.
    **_rules("pr-target-checkout issue-comment-pr-checkout workflow-run-artifact-poisoning "
             "cache-poisoning-pr-target self-hosted-pr script-injection github-script-injection "
             "github-env-injection", _FORK, {"ci_code_exec"}),
    **_rules("secrets-inherit secret-in-run", _CI, {"secrets"}),
    **_rules("default-token-permissions broad-permissions checkout-persist-credentials", _CI, {"ci_token"}),
    **_rules("oidc-on-untrusted-trigger", _CI, {"cloud_creds"}),
    # Cloud: SSRF to instance metadata, then IAM self-escalation (#241, #370).
    **_rules("imds-v1-enabled", frozenset({"internal_network"}), {"cloud_creds"}),
    **_rules("iam-privilege-escalation", frozenset({"cloud_creds"}), {"cloud_admin"}),
}

# Steps that join two artifacts (app code and the config it runs under) state
# the assumption that links them.
_NOTES: dict[str, str] = {
    **dict.fromkeys(
        "privileged-container host-path-mount host-namespace-shared dangerous-capability "
        "rbac-secret-access cluster-admin-binding rbac-wildcard rbac-escalation".split(),
        "assumes the exploited code runs in the workload this setting configures",
    ),
    "imds-v1-enabled": "assumes the SSRF-reachable code runs on this instance",
    "iam-privilege-escalation": "assumes the stolen credentials belong to a principal with this policy",
}
# Code execution in one workflow doesn't reach another workflow's secrets or
# token: steps that need it must be in the file that grants it.
_FILE_SCOPED: frozenset[Capability] = frozenset({"ci_code_exec"})
_CONFIDENCE = {"high": 0.8, "medium": 0.6, "low": 0.4}
_MAX_DEPTH = 6


def evidence_id(rule: str, location: FindingLocation | None) -> str:
    """`<rule>@<file>:<line>`, or the bare rule for a repo-level finding."""
    if location is None:
        return rule
    return f"{rule}@{location.file}:{location.line if location.line is not None else ''}"


def _step(rule: str, finding: Finding, location: FindingLocation | None) -> ChainStep:
    requires, grants = STEP_LIBRARY[rule]
    notes = [_NOTES[rule]] if rule in _NOTES else []
    return ChainStep(
        id=evidence_id(rule, location),
        rule_id=rule,
        title=finding.title,
        technique=finding.attack_techniques[0] if finding.attack_techniques else None,
        requires=sorted(requires),
        grants=sorted(grants),
        evidence_ids=[evidence_id(rule, location)],
        location=location,
        confidence=_CONFIDENCE[finding.confidence],
        precondition_notes=notes,
    )


def _closure(caps: Iterable[Capability]) -> set[Capability]:
    out = set(caps)
    for cap in list(out):
        out |= IMPLIES.get(cap, frozenset())
    return out


def build_attack_chains(findings: list[Finding]) -> list[AttackChain]:
    """One best chain per goal capability, with at least two steps."""
    # One step per rule, or per (rule, workflow file) where a capability is
    # file-scoped: the best-confidence finding wins.
    steps: dict[tuple[str, str], ChainStep] = {}
    for finding in findings:
        rule = finding_rule_id(finding)
        if rule not in STEP_LIBRARY:
            continue
        scoped = bool(_FILE_SCOPED & (STEP_LIBRARY[rule][0] | STEP_LIBRARY[rule][1]))
        for location in finding.locations or [None]:
            key = (rule, location.file if scoped and location else "")
            step = _step(rule, finding, location)
            if key not in steps or step.confidence > steps[key].confidence:
                steps[key] = step
            if not scoped:
                break
    granting: dict[Capability, list[ChainStep]] = {}
    for step in steps.values():
        for cap in _closure(step.grants):
            granting.setdefault(cap, []).append(step)

    def best(
        cap: Capability, visiting: frozenset[Capability], depth: int, file: str | None = None
    ) -> list[ChainStep] | None:
        if cap in START:
            return []
        if depth > _MAX_DEPTH or cap in visiting:
            return None
        found: list[ChainStep] | None = None
        for step in granting.get(cap, []):
            if file is not None and (step.location is None or step.location.file != file):
                continue
            path: list[ChainStep] | None = []
            for req in step.requires:
                scope = step.location.file if req in _FILE_SCOPED and step.location else None
                sub = best(req, visiting | {cap}, depth + 1, scope)
                if sub is None:
                    path = None
                    break
                path += [s for s in sub if s not in path]
            if path is None:
                continue
            path.append(step)
            if found is None or _likelihood(path) > _likelihood(found):
                found = path
        return found

    chains: list[AttackChain] = []
    seen: set[tuple[str, ...]] = set()
    for goal in GOALS:
        path = best(goal, frozenset(), 0)
        if not path or len(path) < 2:
            continue
        key = tuple(step.id for step in path)
        if key in seen:
            continue
        seen.add(key)
        chains.append(
            AttackChain(
                id=f"chain:{len(chains) + 1}",
                start=sorted(START & {r for s in path for r in s.requires}),
                steps=path,
                impact=goal,
                likelihood=round(_likelihood(path), 3),
            )
        )
    return chains


def _likelihood(path: list[ChainStep]) -> float:
    out = 1.0
    for step in path:
        out *= step.confidence
    return out


__all__ = ["GOALS", "START", "STEP_LIBRARY", "build_attack_chains", "evidence_id"]
