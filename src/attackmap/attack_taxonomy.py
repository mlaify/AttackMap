"""MITRE ATT&CK technique mapping for AttackMap insights and findings.

Maps internal `InsightKind` values to ATT&CK techniques (Enterprise
matrix). Findings map through their rule id (`taxonomy.py`, #250); a
whole-word title fallback covers only findings with no registered rule.
Conservative by design — we only emit techniques where the static-analysis
evidence directly motivates the mapping. Defenders use these to slot AttackMap output into existing
ATT&CK-aligned detection programs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import AttackTechnique, Finding, Insight, InsightKind
from .taxonomy import ATTACK_TECHNIQUES, attack_url, taxonomy_for


def _technique(technique_id: str) -> AttackTechnique:
    name, tactic = ATTACK_TECHNIQUES[technique_id]
    return AttackTechnique(technique_id=technique_id, name=name, tactic=tactic, url=attack_url(technique_id))


# Technique catalog, shared with the per-rule registry (`taxonomy.py`).
T = {tid: _technique(tid) for tid in ATTACK_TECHNIQUES}


@dataclass(frozen=True)
class _Mapping:
    technique_ids: tuple[str, ...]


_INSIGHT_KIND_MAP: dict[InsightKind, _Mapping] = {
    "shared_secret_blast_radius": _Mapping(("T1552", "T1528", "T1078")),
    "sensitive_asset_reachability": _Mapping(("T1190", "T1041")),
    "control_bypass": _Mapping(("T1685", "T1190")),
    "defense_gap_in_chain": _Mapping(("T1190", "T1212")),
    "asymmetric_protection": _Mapping(("T1190", "T1078")),
    "trust_boundary_violation": _Mapping(("T1199", "T1190")),
    "audit_gap": _Mapping(("T1685",)),
    "control_strength_mismatch": _Mapping(("T1110", "T1552")),
    "single_point_of_failure": _Mapping(("T1552", "T1528", "T1556")),
    "stale_or_contradictory_signal": _Mapping(()),
    "admin_action_without_auth": _Mapping(("T1078", "T1068", "T1098")),
}


# Fallback for findings whose rule id isn't in the taxonomy registry (plugin
# findings): whole-word matches against the title only — never evidence, which
# carries repo text ("monkey", "cursor.execute", "author") (#250).
_FINDING_KEYWORD_MAP: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("webhook", "webhooks", "callback", "callbacks"), ("T1190", "T1199")),
    (("admin", "administrative", "privileged"), ("T1078", "T1068", "T1098")),
    (("upload", "uploads"), ("T1190", "T1505.003")),
    (("auth", "authentication", "login", "session", "sessions"), ("T1078", "T1110", "T1556")),
    (("secret", "secrets", "token", "tokens", "key", "keys", "credential", "credentials"), ("T1552", "T1528")),
    (("rce", "command execution", "command injection"), ("T1059",)),
)
_KEYWORD_PATTERNS = tuple(
    (re.compile(r"\b(?:" + "|".join(re.escape(k) for k in keywords) + r")\b"), tids)
    for keywords, tids in _FINDING_KEYWORD_MAP
)


def techniques_for_insight(insight: Insight) -> list[AttackTechnique]:
    mapping = _INSIGHT_KIND_MAP.get(insight.kind)
    if mapping is None:
        return []
    return [T[tid] for tid in mapping.technique_ids if tid in T]


def techniques_for_finding(finding: Finding) -> list[AttackTechnique]:
    """ATT&CK techniques for a finding: the registry entry for its rule id
    when there is one, else the whole-word title fallback."""
    entry = taxonomy_for(finding.rule_id)
    if entry is not None:
        if entry.attack:
            return [T[tid] for tid in entry.attack]
        return list(finding.attack_techniques)
    if finding.attack_techniques:
        return list(finding.attack_techniques)
    title = finding.title.lower()
    seen: set[str] = set()
    matched: list[AttackTechnique] = []
    for pattern, technique_ids in _KEYWORD_PATTERNS:
        if not pattern.search(title):
            continue
        for tid in technique_ids:
            if tid not in seen:
                seen.add(tid)
                matched.append(T[tid])
    return matched


def annotate_insights(insights: list[Insight]) -> list[Insight]:
    """Return new Insight objects with `attack_techniques` populated.

    Insights are immutable pydantic models, so we model_copy with an update.
    """
    annotated: list[Insight] = []
    for insight in insights:
        if insight.attack_techniques:
            annotated.append(insight)
            continue
        techniques = techniques_for_insight(insight)
        if not techniques:
            annotated.append(insight)
            continue
        annotated.append(insight.model_copy(update={"attack_techniques": techniques}))
    return annotated


def annotate_findings(findings: list[Finding]) -> list[Finding]:
    annotated: list[Finding] = []
    for finding in findings:
        if finding.attack_techniques:
            annotated.append(finding)
            continue
        techniques = techniques_for_finding(finding)
        if not techniques:
            annotated.append(finding)
            continue
        annotated.append(finding.model_copy(update={"attack_techniques": techniques}))
    return annotated


__all__ = [
    "techniques_for_insight",
    "techniques_for_finding",
    "annotate_insights",
    "annotate_findings",
]
