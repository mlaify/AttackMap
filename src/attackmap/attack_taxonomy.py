"""MITRE ATT&CK technique mapping for AttackMap insights and findings.

Maps internal `InsightKind` values and finding-title keywords to relevant
ATT&CK techniques (Enterprise matrix). Conservative by design — we only
emit techniques where the static-analysis evidence directly motivates
the mapping. Defenders use these to slot AttackMap output into existing
ATT&CK-aligned detection programs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import AttackTechnique, Finding, Insight, InsightKind


def _technique(technique_id: str, name: str, tactic: str) -> AttackTechnique:
    return AttackTechnique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


# Curated technique catalog — only techniques AttackMap actually maps to.
T = {
    "T1190": _technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1078": _technique("T1078", "Valid Accounts", "Defense Evasion / Persistence / Initial Access"),
    "T1199": _technique("T1199", "Trusted Relationship", "Initial Access"),
    "T1212": _technique("T1212", "Exploitation for Credential Access", "Credential Access"),
    "T1552": _technique("T1552", "Unsecured Credentials", "Credential Access"),
    "T1110": _technique("T1110", "Brute Force", "Credential Access"),
    "T1528": _technique("T1528", "Steal Application Access Token", "Credential Access"),
    "T1068": _technique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1098": _technique("T1098", "Account Manipulation", "Persistence / Privilege Escalation"),
    "T1562": _technique("T1562", "Impair Defenses", "Defense Evasion"),
    "T1565": _technique("T1565", "Data Manipulation", "Impact"),
    "T1485": _technique("T1485", "Data Destruction", "Impact"),
    "T1041": _technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "T1071": _technique("T1071", "Application Layer Protocol", "Command and Control"),
    "T1059": _technique("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1556": _technique("T1556", "Modify Authentication Process", "Defense Evasion / Persistence"),
}


@dataclass(frozen=True)
class _Mapping:
    technique_ids: tuple[str, ...]


_INSIGHT_KIND_MAP: dict[InsightKind, _Mapping] = {
    "shared_secret_blast_radius": _Mapping(("T1552", "T1528", "T1078")),
    "sensitive_asset_reachability": _Mapping(("T1190", "T1041")),
    "control_bypass": _Mapping(("T1562", "T1190")),
    "defense_gap_in_chain": _Mapping(("T1190", "T1212")),
    "asymmetric_protection": _Mapping(("T1190", "T1078")),
    "trust_boundary_violation": _Mapping(("T1199", "T1190")),
    "audit_gap": _Mapping(("T1562",)),
    "control_strength_mismatch": _Mapping(("T1110", "T1552")),
    "single_point_of_failure": _Mapping(("T1552", "T1528", "T1556")),
    "stale_or_contradictory_signal": _Mapping(()),
    "admin_action_without_auth": _Mapping(("T1078", "T1068", "T1098")),
}


# Title/evidence keyword fallback for findings (which don't carry a kind enum).
_FINDING_KEYWORD_MAP: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("webhook", "callback"), ("T1190", "T1199")),
    (("admin", "manage", "privileged"), ("T1078", "T1068", "T1098")),
    (("upload",), ("T1190", "T1059")),
    (("auth", "login", "session"), ("T1078", "T1110", "T1556")),
    (("secret", "token", "key"), ("T1552", "T1528")),
    (("public route", "external"), ("T1190",)),
    (("exfil",), ("T1041",)),
    (("command", "rce", "exec"), ("T1059",)),
    (("data store", "datastore", "database"), ("T1565",)),
)


def techniques_for_insight(insight: Insight) -> list[AttackTechnique]:
    mapping = _INSIGHT_KIND_MAP.get(insight.kind)
    if mapping is None:
        return []
    return [T[tid] for tid in mapping.technique_ids if tid in T]


def techniques_for_finding(finding: Finding) -> list[AttackTechnique]:
    haystack = " ".join([finding.title, *finding.evidence]).lower()
    seen: set[str] = set()
    matched: list[AttackTechnique] = []
    for keywords, technique_ids in _FINDING_KEYWORD_MAP:
        if not any(keyword in haystack for keyword in keywords):
            continue
        for tid in technique_ids:
            if tid in seen or tid not in T:
                continue
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
