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
    appending ``-2``, ``-3``, … in input order. Deterministic for a given input.
    """
    ids: list[str] = []
    seen: dict[str, int] = {}
    for path in paths:
        base = _slug(path.name)
        seen[base] = seen.get(base, 0) + 1
        ids.append(base if seen[base] == 1 else f"{base}-{seen[base]}")
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

    lines.append(
        "_Phase 1 (#146a): per-repo reports assembled into a fleet view. "
        "Cross-repo contract linking, cross-boundary taint, and trust-gap "
        "detection land in #146b–#146d._"
    )
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
    }


__all__ = [
    "FleetRepoResult",
    "FleetScan",
    "fleet_repo_ids",
    "fleet_summary_json",
    "render_fleet_summary",
]
