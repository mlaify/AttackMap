from __future__ import annotations

import json
from pathlib import Path

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
from .topology import build_service_graph


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


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
) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "architecture.md").write_text(architecture_md + "\n", encoding="utf-8")
    (out / "attack-surface.md").write_text(attack_surface_md + "\n", encoding="utf-8")
    (out / "defensive-review.md").write_text(defensive_review_md + "\n", encoding="utf-8")
    defensive_review_json = build_defensive_review_json(scan, attack_surfaces, findings, attack_paths)
    (out / "defensive-review.json").write_text(json.dumps(defensive_review_json, indent=2) + "\n", encoding="utf-8")
    review_context_pack = build_review_context_pack(
        defensive_review_json,
        scan,
        analyzer_metadata if analyzer_metadata is not None else [],
    )
    (out / "review-context-pack.json").write_text(json.dumps(review_context_pack, indent=2) + "\n", encoding="utf-8")

    exploitability = score_exploitability(scan, attack_surfaces)
    (out / "attackmap-exploitability.md").write_text(
        render_exploitability_ranking(exploitability) + "\n", encoding="utf-8"
    )

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
        "attack_paths": [path.model_dump() for path in attack_paths],
        "exploitability": [score.model_dump() for score in exploitability],
    }
    (out / "attackmap-report.json").write_text(json.dumps(json_report, indent=2) + "\n", encoding="utf-8")

    # SARIF 2.1.0 for GitHub Code Scanning / VS Code / other SARIF
    # consumers. Emitted alongside JSON, not in place of it.
    sarif_report = build_sarif(findings, attack_paths)
    (out / "attackmap-report.sarif").write_text(
        json.dumps(sarif_report, indent=2) + "\n", encoding="utf-8"
    )

    # Mermaid + Graphviz DOT export of attack paths and service topology
    # (#49). Nothing new is computed — pure output transform of shapes
    # that already exist in the JSON report.
    service_graph = build_service_graph(scan)
    (out / "attackmap-paths.md").write_text(
        render_attack_paths_mermaid(attack_paths), encoding="utf-8"
    )
    (out / "attackmap-topology.md").write_text(
        render_topology_mermaid(service_graph), encoding="utf-8"
    )
    (out / "attackmap-paths.dot").write_text(
        render_attack_paths_dot(attack_paths), encoding="utf-8"
    )
    (out / "attackmap-topology.dot").write_text(
        render_topology_dot(service_graph), encoding="utf-8"
    )


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


def render_pr_comment(findings: list[Finding], diff: object | None = None) -> str:
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
        lines.append(f"**{len(new)} new**, **{len(resolved)} resolved** vs. baseline — {gate}.")
        lines.append("")
        if new:
            lines.append("### New findings")
            for s in sorted(new, key=lambda s: sev_rank.get(s.severity, 3)):
                lines.append(f"- **[{s.severity.upper()}]** {s.title}")
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
                f"- `{f.exploitability}/100` **{(f.exploitability_tier or '').upper()}** — {f.title}"
            )
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
