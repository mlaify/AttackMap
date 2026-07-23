"""Fleet (multi-repo) container + summary rendering — cross-repo phase 1 (#146a).

The lowest-blast-radius shape for cross-repo analysis (epic #150): rather than
merge N repos into one `ScanResult` (which would force a repo id onto every
signal model and rewrite the scanner's path relativization), each repo is
scanned independently into its own `ScanResult` — its own root, its own
relative paths, no collisions — and the results are collected into a `FleetScan`
over which later phases (#146b–#146d: contract linking, cross-boundary taint,
trust-gap) will reason.

This module is deliberately pure: the CLI does the per-repo scanning (reusing
the same building blocks a single-repo run uses) and hands the results here for
identity assignment and summary rendering, so the logic stays unit-testable
without a real scan. Phase 1 adds **no** cross-repo detection — it is the
foundation the seam-analysis phases build on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .contracts import ContractLink
from .crossrepo import CrossBoundaryFlow

if TYPE_CHECKING:
    from .models import AttackPath, Finding, ScanResult

_SLUG_RE = re.compile(r"[^a-z0-9]+")

_SEVERITIES = ("high", "medium", "low")


def _slug(name: str) -> str:
    """A filesystem- and link-safe slug for a repo directory name."""
    s = _SLUG_RE.sub("-", name.lower()).strip("-")
    return s or "repo"


def fleet_repo_ids(paths: list[Path]) -> list[str]:
    """Stable, unique per-repo identifiers derived from the directory names.

    Two repos with the same basename (``a/service`` and ``b/service``) would
    collide into one report subdirectory, so collisions are disambiguated by
    appending ``-2``, ``-3``, … in input order. Each candidate is checked against
    **every id already emitted** — not just a per-base counter — so a suffix that
    coincides with a later input's own name (``api``, ``api``, ``api-2`` →
    ``api``, ``api-2``, ``api-2-2``) still stays globally unique. Deterministic.
    """
    ids: list[str] = []
    used: set[str] = set()
    for path in paths:
        base = _slug(path.name)
        candidate = base
        n = 1
        while candidate in used:
            n += 1
            candidate = f"{base}-{n}"
        used.add(candidate)
        ids.append(candidate)
    return ids


@dataclass
class FleetRepoResult:
    """One repo's analysis within a fleet run."""

    repo_id: str
    root: str  # absolute path scanned
    report_dir: str  # where this repo's reports were written (output/<repo_id>)
    scan: "ScanResult"
    findings: list["Finding"]
    attack_paths: list["AttackPath"] = field(default_factory=list)
    suppressed_count: int = 0

    def severity_counts(self) -> dict[str, int]:
        counts = {sev: 0 for sev in _SEVERITIES}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts


@dataclass
class FleetScan:
    """A multi-repo analysis run — the input surface for cross-repo phases."""

    results: list[FleetRepoResult] = field(default_factory=list)
    # Cross-repo client→server contract links (#146b), computed once all repos
    # are scanned. Empty until the linker runs.
    links: list[ContractLink] = field(default_factory=list)
    # Cross-boundary trust flows (#146c) — confused-deputy leads over the links.
    cross_boundary: list[CrossBoundaryFlow] = field(default_factory=list)

    @property
    def repo_count(self) -> int:
        return len(self.results)

    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)


def _top_findings(result: FleetRepoResult, limit: int = 3) -> list["Finding"]:
    order = {sev: i for i, sev in enumerate(_SEVERITIES)}
    ranked = sorted(
        result.findings,
        key=lambda f: (order.get(f.severity, 99), -(f.score or 0), f.title),
    )
    return ranked[:limit]


def render_fleet_summary(fleet: FleetScan) -> str:
    """A Markdown fleet index: one row per repo with a severity breakdown, plus
    each repo's top findings and a link to its per-repo report directory."""
    lines: list[str] = ["# AttackMap fleet summary", ""]
    lines.append(
        f"{fleet.repo_count} repositories analyzed · "
        f"{fleet.total_findings()} finding(s) total."
    )
    lines.append("")
    lines.append("| Repository | HIGH | MED | LOW | Total | Report |")
    lines.append("|---|---:|---:|---:|---:|---|")
    for r in fleet.results:
        c = r.severity_counts()
        total = len(r.findings)
        lines.append(
            f"| `{r.repo_id}` | {c['high']} | {c['medium']} | {c['low']} | "
            f"{total} | [{r.repo_id}/]({r.repo_id}/) |"
        )
    lines.append("")

    for r in fleet.results:
        lines.append(f"## `{r.repo_id}`")
        lines.append("")
        lines.append(f"- Path: `{r.root}`")
        lines.append(f"- Findings: {len(r.findings)} ({r.suppressed_count} suppressed)")
        top = _top_findings(r)
        if top:
            lines.append("- Top findings:")
            for f in top:
                lines.append(f"  - **[{f.severity.upper()}]** {f.title}")
        lines.append("")

    lines.append("## Cross-repo links (#146b)")
    lines.append("")
    if fleet.links:
        loc = lambda f, ln: f"{f}:{ln}" if ln else f  # noqa: E731
        lines.append(
            f"{len(fleet.links)} client→server contract link(s) — an outbound call "
            "in one repo matched to a route another repo serves:"
        )
        lines.append("")
        lines.append("| Client | Call | → | Server | Route |")
        lines.append("|---|---|---|---|---|")
        for lk in fleet.links:
            lines.append(
                f"| `{lk.client_repo}` | `{lk.method} {lk.client_target}` "
                f"[{loc(lk.client_file, lk.client_line)}] | → | `{lk.server_repo}` | "
                f"`{lk.method} {lk.server_route_path}` [{loc(lk.server_file, lk.server_line)}] |"
            )
        lines.append("")
    else:
        lines.append("_No cross-repo client→server HTTP links detected._")
        lines.append("")

    lines.append("## Cross-boundary trust (#146c)")
    lines.append("")
    if fleet.cross_boundary:
        loc = lambda f, ln: f"{f}:{ln}" if ln else f  # noqa: E731
        lines.append(
            f"{len(fleet.cross_boundary)} SPECULATIVE confused-deputy flow(s) — a "
            "value forwarded across a link that the callee trusts into a sink or "
            "unguarded object access. Adjudicate before acting:"
        )
        lines.append("")
        for cb in fleet.cross_boundary:
            what = (
                f"reaches a {cb.detail} sink"
                if cb.basis == "taint"
                else f"is an unguarded {cb.detail}"
            )
            lines.append(
                f"- **[{cb.severity.upper()}, SPECULATIVE]** `{cb.client_repo}` calls "
                f"`{cb.method} {cb.route}` served by `{cb.server_repo}`, which {what} — "
                f"the caller's value is trusted without the callee re-validating. "
                f"Caller: `{cb.client_target}` [{loc(cb.client_file, cb.client_line)}]; "
                f"callee: [{loc(cb.server_file, cb.server_line)}]."
            )
        lines.append("")
    else:
        lines.append("_No cross-boundary trust flows detected._")
        lines.append("")

    lines.append("_Trust-assumption-gap and cross-repo anomaly detection land in #146d._")
    return "\n".join(lines)


def render_fleet_graph_mermaid(fleet: FleetScan) -> str:
    """A Mermaid flowchart of the fleet: one node per repo, one edge per distinct
    client→server route link (labeled with the served contract)."""
    lines = ["```mermaid", "flowchart LR"]
    ids = {r.repo_id for r in fleet.results}
    node_id = {rid: f"R{i}" for i, rid in enumerate(sorted(ids))}
    for rid in sorted(ids):
        lines.append(f'    {node_id[rid]}["{rid}"]')
    # Collapse multiple links between the same pair to one edge per route.
    seen: set[tuple[str, str, str, str]] = set()
    for lk in fleet.links:
        edge = (lk.client_repo, lk.server_repo, lk.method, lk.path_template)
        if edge in seen or lk.client_repo not in node_id or lk.server_repo not in node_id:
            continue
        seen.add(edge)
        label = f"{lk.method} /{lk.path_template}"
        lines.append(f'    {node_id[lk.client_repo]} -->|"{label}"| {node_id[lk.server_repo]}')
    lines.append("```")
    return "\n".join(lines)


def fleet_summary_json(fleet: FleetScan) -> dict:
    """Machine-readable fleet index (for GUI / tooling front-ends)."""
    return {
        "repo_count": fleet.repo_count,
        "total_findings": fleet.total_findings(),
        "repos": [
            {
                "repo_id": r.repo_id,
                "root": r.root,
                "report_dir": r.report_dir,
                "findings": len(r.findings),
                "suppressed": r.suppressed_count,
                "severity_counts": r.severity_counts(),
            }
            for r in fleet.results
        ],
        "cross_repo_links": [
            {
                "client_repo": lk.client_repo,
                "server_repo": lk.server_repo,
                "method": lk.method,
                "path_template": lk.path_template,
                "client_target": lk.client_target,
                "client_location": f"{lk.client_file}:{lk.client_line}"
                if lk.client_line
                else lk.client_file,
                "server_route_path": lk.server_route_path,
                "server_location": f"{lk.server_file}:{lk.server_line}"
                if lk.server_line
                else lk.server_file,
            }
            for lk in fleet.links
        ],
        "cross_boundary_flows": [
            {
                "client_repo": cb.client_repo,
                "server_repo": cb.server_repo,
                "method": cb.method,
                "route": cb.route,
                "basis": cb.basis,
                "detail": cb.detail,
                "severity": cb.severity,
                "speculative": True,
                "client_location": f"{cb.client_file}:{cb.client_line}"
                if cb.client_line
                else cb.client_file,
                "server_location": f"{cb.server_file}:{cb.server_line}"
                if cb.server_line
                else cb.server_file,
            }
            for cb in fleet.cross_boundary
        ],
    }


__all__ = [
    "FleetRepoResult",
    "FleetScan",
    "fleet_repo_ids",
    "fleet_summary_json",
    "render_fleet_graph_mermaid",
    "render_fleet_summary",
]
