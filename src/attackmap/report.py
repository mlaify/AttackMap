from __future__ import annotations

import json
from pathlib import Path

from .md import md_code, md_text
from .context_pack import build_review_context_pack
from .diagrams import (
    render_attack_paths_dot,
    render_attack_paths_mermaid,
    render_topology_dot,
    render_topology_mermaid,
)
from .diff import finding_id
from .exploitability import score_exploitability
from .models import AttackPath, AttackSurface, ExploitabilityScore, Finding, ScanResult
from .review_json import build_defensive_review_json
from .sarif import build_sarif
from .safe_fs import ensure_output_dir, safe_write_text
from .suppress import SuppressedFinding
from .topology import build_service_graph


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


# Values accepted by ``--format`` / ``write_reports(output_format=...)``.
OUTPUT_FORMATS = ("all", "markdown", "json")


def write_reports(
    output_dir: str | Path,
    scan: ScanResult,
    architecture_md: str,
    attack_surface_md: str,
    defensive_review_md: str,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    analyzer_metadata: list[dict[str, object]] | None = None,
    suppressed: list[SuppressedFinding] | None = None,
    output_format: str = "all",
) -> None:
    """Write the report set for one scan.

    ``output_format`` selects which artifacts are emitted (``--format``):
    ``"json"`` writes the machine-readable files (``*.json`` + SARIF),
    ``"markdown"`` writes the human-readable files (``*.md`` + Graphviz
    ``*.dot``), and ``"all"`` (default) writes both.
    """
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(
            f"Unknown output format {output_format!r}; expected one of: {', '.join(OUTPUT_FORMATS)}."
        )
    emit_json = output_format in {"all", "json"}
    emit_markdown = output_format in {"all", "markdown"}

    out = ensure_output_dir(output_dir)
    suppressed = suppressed or []

    def write(name: str, text: str) -> None:
        safe_write_text(out, out / name, text)

    if emit_markdown:
        write("architecture.md", architecture_md + "\n")
        write("attack-surface.md", attack_surface_md + "\n")
        write("defensive-review.md", defensive_review_md + "\n")
    defensive_review_json = build_defensive_review_json(scan, attack_surfaces, findings, attack_paths)
    review_context_pack = build_review_context_pack(
        defensive_review_json,
        scan,
        analyzer_metadata if analyzer_metadata is not None else [],
    )
    if emit_json:
        write("defensive-review.json", json.dumps(defensive_review_json, indent=2) + "\n")
        write("review-context-pack.json", json.dumps(review_context_pack, indent=2) + "\n")

    exploitability = score_exploitability(scan, attack_surfaces)
    if emit_markdown:
        write("attackmap-exploitability.md", render_exploitability_ranking(exploitability) + "\n")

    json_report = {
        "scan": scan.model_dump(),
        "architecture_summary": architecture_md,
        "attack_surface_summary": attack_surface_md,
        "defensive_review": defensive_review_md,
        "defensive_review_json": defensive_review_json,
        "review_context_pack": review_context_pack,
        "attack_surfaces": [surface.model_dump() for surface in attack_surfaces],
        "findings": [
            {"id": finding_id(finding.title), **finding.model_dump()} for finding in findings
        ],
        # Suppressed findings are retained (not dropped) with their reason so
        # audits can see what was silenced and why (#144).
        "suppressed_findings": [
            {
                "id": s.id,
                "rule": s.rule,
                "reason": s.reason,
                "suppressed_by": [m.label() for m in s.matched],
                **s.finding.model_dump(),
            }
            for s in suppressed
        ],
        "attack_paths": [path.model_dump() for path in attack_paths],
        "exploitability": [score.model_dump() for score in exploitability],
    }
    if emit_json:
        write("attackmap-report.json", json.dumps(json_report, indent=2) + "\n")

        # SARIF 2.1.0 for GitHub Code Scanning / VS Code / other SARIF
        # consumers. Emitted alongside JSON, not in place of it.
        sarif_report = build_sarif(
            findings,
            attack_paths,
            suppressed=[(s.finding, s.reason) for s in suppressed],
        )
        write("attackmap-report.sarif", json.dumps(sarif_report, indent=2) + "\n")

    if not emit_markdown:
        return

    # Mermaid + Graphviz DOT export of attack paths and service topology
    # (#49). Nothing new is computed — pure output transform of shapes
    # that already exist in the JSON report.
    service_graph = build_service_graph(scan)
    write("attackmap-paths.md", render_attack_paths_mermaid(attack_paths))
    write("attackmap-topology.md", render_topology_mermaid(service_graph))
    write("attackmap-paths.dot", render_attack_paths_dot(attack_paths))
    write("attackmap-topology.dot", render_topology_dot(service_graph))


def render_exploitability_ranking(scores: list[ExploitabilityScore]) -> str:
    """Render the 'Most exploitable now' section — fused route→sink risk,
    ranked, with every score showing its contributing factors."""
    lines = ["# Most exploitable now", ""]
    if not scores:
        lines.append(
            "No request-to-sink data-flow paths were found, so there is nothing to "
            "fuse into an exploitability ranking."
        )
        return "\n".join(lines)
    lines.append(
        "Fused 0–100 exploitability for each route→sink path (deterministic; every "
        "score is the clamped sum of the listed factors). Highest risk first."
    )
    lines.append("")
    for rank, s in enumerate(scores, start=1):
        lines.append(f"## {rank}. {s.subject} — {s.score}/100 ({s.tier.upper()})")
        lines.append(f"- sink location: `{s.location}`")
        lines.append("- factors:")
        for f in s.factors:
            sign = "+" if f.points >= 0 else ""
            lines.append(f"    - {sign}{f.points}  {f.name} — {f.detail}")
        if s.raw_score != s.score:
            lines.append(f"    - (raw {s.raw_score} clamped to {s.score})")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_pr_comment(
    findings: list[Finding], diff: object | None = None, *, suppressions: dict | None = None
) -> str:
    """Render a compact Markdown PR summary comment (#105).

    With a `DiffReport` (duck-typed: `.new`/`.resolved`/`.has_new_high`), leads
    with what the PR introduced/resolved; otherwise summarizes current findings.
    Always surfaces the top 'most exploitable now' entries. Pure function —
    the GitHub Action posts the string via `gh pr comment` / github-script."""
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    lines = ["## 🗺️ AttackMap security review", ""]

    new = list(getattr(diff, "new", []) or []) if diff is not None else []
    resolved = list(getattr(diff, "resolved", []) or []) if diff is not None else []

    if diff is not None:
        gate = "⚠️ introduces new HIGH-severity findings" if getattr(diff, "has_new_high", False) else "no new HIGH findings"
        new_instances = list(getattr(diff, "new_instances", []) or [])
        instance_total = sum(len(labels) for _, labels in new_instances)
        lines.append(
            f"**{len(new)} new**, **{instance_total} new instance(s) of existing findings**, "
            f"**{len(resolved)} resolved** vs. baseline — {gate}."
        )
        lines.append("")
        if new:
            lines.append("### New findings")
            for s in sorted(new, key=lambda s: sev_rank.get(s.severity, 3)):
                lines.append(f"- **[{s.severity.upper()}]** {md_text(s.title)}")
            lines.append("")
        newly_suppressed = list(getattr(diff, "newly_suppressed", []) or [])
        if newly_suppressed:
            lines.append("### Newly suppressed in this change")
            lines.append("_Active in the baseline, silenced by a suppression added here — review the reason._")
            for s in sorted(newly_suppressed, key=lambda s: sev_rank.get(s.severity, 3)):
                lines.append(f"- **[{s.severity.upper()}]** {md_text(s.title)}")
            lines.append("")
        if new_instances:
            lines.append("### New instances of existing findings")
            for s, labels in sorted(new_instances, key=lambda t: sev_rank.get(t[0].severity, 3)):
                where = ", ".join(md_code(label) for label in labels[:5])
                more = f" (+{len(labels) - 5} more)" if len(labels) > 5 else ""
                lines.append(f"- **[{s.severity.upper()}]** {md_text(s.title)}: {where}{more}")
            lines.append("")
    else:
        by_sev = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        lines.append(
            f"**{by_sev['high']} high**, **{by_sev['medium']} medium**, **{by_sev['low']} low** findings."
        )
        lines.append("")

    exploitable = sorted(
        (f for f in findings if f.exploitability is not None),
        key=lambda f: -(f.exploitability or 0),
    )
    if exploitable:
        lines.append("### Most exploitable now")
        for f in exploitable[:3]:
            lines.append(
                f"- `{f.exploitability}/100` **{(f.exploitability_tier or '').upper()}** — {md_text(f.title)}"
            )
        lines.append("")

    if suppressions:
        pending = suppressions.get("pending") or []
        by_rule = suppressions.get("by_rule") or {}
        if pending or by_rule:
            lines.append("### Suppressions")
            if pending:
                ref = suppressions.get("trusted_ref") or "the base"
                state = "applied anyway" if suppressions.get("pending_applied") else "**not applied** until merged"
                lines.append(f"{len(pending)} suppression(s) added by this change since {md_code(ref)} — {state}:")
                lines.extend(f"- {md_text(entry)}" for entry in pending[:20])
            if by_rule:
                counts = ", ".join(f"{md_code(rule)} ×{n}" for rule, n in sorted(by_rule.items()))
                lines.append(f"Suppressed by rule: {counts}")
            lines.append("")

    lines.append(
        "<sub>Heuristic static analysis — findings are confidence-tiered evidence, "
        "not proof. See the uploaded SARIF for inline annotations.</sub>"
    )
    return "\n".join(lines)


def render_console_summary(scan: ScanResult, findings: list[Finding], attack_paths: list[AttackPath]) -> str:
    ordered_findings = sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))
    lines = [
        f"Scanned {scan.files_scanned} files",
        f"Detected languages: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"Routes: {len(scan.routes)}",
        f"External calls: {len(scan.external_calls)}",
        f"Datastores: {len(scan.databases)}",
        "",
        "Findings:",
    ]
    for finding in ordered_findings:
        exploit = (
            f"  (exploitability {finding.exploitability}/100, {finding.exploitability_tier})"
            if finding.exploitability is not None
            else ""
        )
        lines.append(f"- [{finding.severity.upper()}] {finding.title}{exploit}")

    exploitable = sorted(
        (f for f in findings if f.exploitability is not None),
        key=lambda f: -(f.exploitability or 0),
    )
    if exploitable:
        lines.append("")
        lines.append("Most exploitable now:")
        for finding in exploitable[:5]:
            lines.append(
                f"- {finding.exploitability}/100 [{finding.exploitability_tier}] {finding.title}"
            )

    lines.append("")
    lines.append("Attack paths:")
    for path in attack_paths:
        lines.append(f"- {path.name}: {path.impact}")

    return "\n".join(lines)
