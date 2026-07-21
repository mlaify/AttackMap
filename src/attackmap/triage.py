"""Deterministic triage fallback (#145).

`--triage` asks an LLM to cluster/dedupe/rank the *existing* heuristic findings
into a prioritized shortlist. When no LLM backend is available it must still
produce a useful, **reproducible** shortlist rather than erroring — that is what
this module does: a score-ordered, root-cause-clustered Markdown view that cites
each finding's stable `finding_id`.

The ordering is a pure function of the findings (severity → exploitability →
score → title), so two runs over the same findings produce byte-identical
output and the file diffs cleanly across scans.
"""

from __future__ import annotations

from .diff import finding_id
from .models import Finding, ScanResult

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

# Root-cause clusters, in fixed priority order. Each maps to the finding tags
# (substring match) that belong to it. The first matching cluster wins.
_CLUSTERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Authorization & access control", ("broken-authorization", "auth-missing", "authorization")),
    ("Injection & unsafe data flow", ("injection", "taint", "ssrf", "ssti", "nosql", "sql", "command", "deserialization", "open-redirect", "traversal")),
    ("Secret exposure", ("secret-exposure", "secret")),
    ("Vulnerable dependencies", ("cve", "dependency")),
    ("Insecure cryptography", ("crypto", "randomness", "tls")),
    ("Web / transport hardening", ("web-hardening", "hardening", "cors", "cookie", "header")),
    ("CI / workflow security", ("workflow", "ci")),
    ("Exposed endpoints & integration", ("exposed-endpoint", "integration-risk", "service-chain", "framework-chain", "atproto-chain")),
)
_FALLBACK_CLUSTER = "Other findings"


def _sort_key(finding: Finding) -> tuple:
    """Deterministic priority key: severity, then exploitability, then score,
    then title (a total order, so output is reproducible)."""
    return (
        _SEVERITY_RANK.get(finding.severity, 3),
        -(finding.exploitability or 0),
        -(finding.score or 0),
        finding.title,
    )


def _cluster_of(finding: Finding) -> tuple[int, str]:
    """Return ``(priority, label)`` for a finding's root-cause cluster."""
    tags = {t.lower() for t in finding.tags}
    for priority, (label, markers) in enumerate(_CLUSTERS):
        if any(any(m in tag for tag in tags) for m in markers):
            return priority, label
    return len(_CLUSTERS), _FALLBACK_CLUSTER


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Findings de-duplicated by ``finding_id`` and ordered deterministically."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        fid = finding_id(finding.title)
        if fid in seen:
            continue
        seen.add(fid)
        unique.append(finding)
    return sorted(unique, key=_sort_key)


def _metrics_suffix(finding: Finding) -> str:
    bits = [finding.severity]
    if finding.exploitability is not None:
        bits.append(f"exploitability {finding.exploitability}")
    elif finding.score is not None:
        bits.append(f"score {finding.score}")
    return ", ".join(bits)


def _rationale(finding: Finding, cluster_size: int) -> str:
    if finding.severity == "high":
        lead = "HIGH severity"
    elif finding.severity == "medium":
        lead = "medium severity"
    else:
        lead = "low severity"
    if finding.exploitability is not None:
        lead += f", exploitability {finding.exploitability}/100"
    if cluster_size > 1:
        lead += f"; clusters with {cluster_size - 1} related finding(s)"
    return lead


def render_triage_fallback(scan: ScanResult, findings: list[Finding]) -> str:
    """Render a deterministic, clustered, ranked triage shortlist in Markdown."""
    ranked = rank_findings(findings)
    if not ranked:
        return (
            "# AttackMap triage shortlist\n\n"
            "_Deterministic prioritization (no LLM backend available)._\n\n"
            "No heuristic findings to triage.\n"
        )

    # Group into clusters, preserving each finding's global rank order.
    clusters: dict[str, list[Finding]] = {}
    cluster_priority: dict[str, int] = {}
    for finding in ranked:
        priority, label = _cluster_of(finding)
        clusters.setdefault(label, []).append(finding)
        cluster_priority[label] = priority

    # Order clusters by the severity of their best finding, then fixed priority
    # — the cluster that most needs attention leads, deterministically.
    ordered_labels = sorted(
        clusters,
        key=lambda label: (_sort_key(clusters[label][0])[0], cluster_priority[label], label),
    )

    lines: list[str] = [
        "# AttackMap triage shortlist",
        "",
        f"_Deterministic prioritization of {len(ranked)} existing finding(s) "
        "(no LLM backend available). Ordered by severity, exploitability, then "
        "score; clustered by root cause._",
        "",
    ]

    rank = 0
    for label in ordered_labels:
        group = clusters[label]
        lines.append(f"## {label} ({len(group)})")
        lines.append("")
        for finding in group:
            rank += 1
            fid = finding_id(finding.title)
            lines.append(
                f"{rank}. `{fid}` — **{finding.title}** ({_metrics_suffix(finding)})"
            )
            lines.append(f"   - {_rationale(finding, len(group))}")
        lines.append("")

    top = ranked[0]
    _, top_label = _cluster_of(top)
    lines.append("## Start here")
    lines.append("")
    lines.append(
        f"Top priority: `{finding_id(top.title)}` — **{top.title}** "
        f"(cluster: {top_label}). Work the shortlist top-down."
    )
    lines.append("")
    return "\n".join(lines)
