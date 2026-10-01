"""Baseline / diff mode for CI integration (#47).

The design goal is a lightweight PR-integration path that pairs well with
SARIF (#42): a bot comment on the PR, a JSON diff, or a gate that fails
the pipeline on newly-introduced HIGH findings — without needing GitHub
Code Scanning.

## Finding identity

We hash the finding title alone. AttackMap emits one ``Finding`` per
issue-type (a webhook-without-auth finding aggregates every unauthenticated
webhook it saw; a hardcoded-secret finding aggregates every hit). Line
numbers and per-site evidence drift on unrelated commits — the title
carries the semantic identity that survives that drift.

## Diff semantics

Given (baseline, current):

- **new**       — id in current but not in baseline
- **persisted** — id in both (current-side snapshot preserved for context)
- **resolved**  — id in baseline but not in current

We do not track "changed" findings separately. Downstream tooling can
compare per-field on ``persisted`` if it cares (severity uplift, more
evidence, etc.); representing "changed" here would double-count.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .md import md_code, md_text
from .models import Finding

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def finding_id(title: str) -> str:
    """Stable per-finding identifier.

    Truncated sha256 of the title, hex-encoded. 16 hex chars = 64 bits
    of identity — comfortably unique across the space of real finding
    titles emitted by AttackMap.
    """
    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class FindingSnapshot:
    """Diff-friendly view of one finding."""

    id: str
    title: str
    severity: str
    confidence: str
    tags: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    # Per-instance identity (#222): fingerprint -> "file:line" label. Empty for
    # findings without fingerprinted locations (e.g. pre-0.4.32 baselines).
    instances: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_finding(cls, f: Finding) -> "FindingSnapshot":
        return cls(
            id=finding_id(f.title),
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            tags=tuple(f.tags),
            evidence=tuple(f.evidence),
            instances=tuple(
                (loc.fingerprint, f"{loc.file}:{loc.line}" if loc.line else loc.file)
                for loc in f.locations
                if loc.fingerprint
            ),
        )

    @classmethod
    def from_dump(cls, d: dict[str, Any]) -> "FindingSnapshot":
        title = str(d.get("title", ""))
        instances = []
        for loc in d.get("locations") or ():
            if isinstance(loc, dict) and loc.get("fingerprint"):
                label = f"{loc.get('file')}:{loc['line']}" if loc.get("line") else str(loc.get("file"))
                instances.append((str(loc["fingerprint"]), label))
        return cls(
            id=finding_id(title),
            title=title,
            severity=str(d.get("severity", "medium")),
            confidence=str(d.get("confidence", "medium")),
            tags=tuple(d.get("tags") or ()),
            evidence=tuple(d.get("evidence") or ()),
            instances=tuple(instances),
        )


@dataclass
class DiffReport:
    new: list[FindingSnapshot] = field(default_factory=list)
    persisted: list[FindingSnapshot] = field(default_factory=list)
    resolved: list[FindingSnapshot] = field(default_factory=list)
    # Persisted findings that gained instances the baseline didn't have (#222):
    # (finding, labels of the new instances).
    new_instances: list[tuple[FindingSnapshot, list[str]]] = field(default_factory=list)
    # Active in the baseline, suppressed now (#224): not a fix, so not
    # "resolved" — surfaced separately and optionally gated.
    newly_suppressed: list[FindingSnapshot] = field(default_factory=list)
    # True when the baseline predates fingerprints, so only whole new
    # findings (not new instances) could be detected.
    baseline_without_instances: bool = False

    @property
    def has_new_high(self) -> bool:
        return any(s.severity == "high" for s in self.new) or any(
            s.severity == "high" for s, _ in self.new_instances
        )

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "persisted": len(self.persisted),
            "resolved": len(self.resolved),
            "new_instances": sum(len(labels) for _, labels in self.new_instances),
            "newly_suppressed": len(self.newly_suppressed),
        }


def diff_findings(
    baseline: list[FindingSnapshot],
    current: list[FindingSnapshot],
    suppressed: list[FindingSnapshot] | None = None,
) -> DiffReport:
    """``suppressed``: findings suppressed in the current run. One that was
    active in the baseline is *newly suppressed*, not resolved (#224)."""
    base_by_id = {s.id: s for s in baseline}
    cur_ids = {s.id for s in current}
    suppressed_ids = {s.id for s in suppressed or []}
    gone = [s for s in baseline if s.id not in cur_ids]
    report = DiffReport(
        new=[s for s in current if s.id not in base_by_id],
        persisted=[s for s in current if s.id in base_by_id],
        resolved=[s for s in gone if s.id not in suppressed_ids],
        newly_suppressed=[s for s in gone if s.id in suppressed_ids],
    )
    report.baseline_without_instances = bool(baseline) and not any(s.instances for s in baseline)
    for snap in report.persisted:
        base = base_by_id[snap.id]
        if not base.instances or not snap.instances:
            continue  # nothing to compare at instance level
        known = {fp for fp, _ in base.instances}
        added = [label for fp, label in snap.instances if fp not in known]
        if added:
            report.new_instances.append((snap, added))
    return report


def load_baseline(path: str | Path) -> list[FindingSnapshot]:
    """Parse a prior ``attackmap-report.json``; return finding snapshots.

    Tolerant of both the full report shape and a bare ``[Finding, …]``
    list — useful for teams that persist just the findings section.
    """
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if isinstance(data, list):
        return [FindingSnapshot.from_dump(d) for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        findings = data.get("findings") or []
        return [FindingSnapshot.from_dump(d) for d in findings if isinstance(d, dict)]
    return []


def render_diff_markdown(diff: DiffReport, *, title: str = "AttackMap diff") -> str:
    """PR-comment-shaped Markdown summary of a diff."""
    counts = diff.counts()

    def _sorted(items: list[FindingSnapshot]) -> list[FindingSnapshot]:
        return sorted(items, key=lambda s: (_SEVERITY_RANK.get(s.severity, 3), s.title))

    def _bullets(items: list[FindingSnapshot]) -> str:
        if not items:
            return "_none_"
        lines = []
        for s in _sorted(items):
            # Titles and evidence embed repo-derived text: escape it (#233).
            lines.append(f"- **[{s.severity.upper()}]** {md_text(s.title)}")
            if s.evidence:
                # First evidence line only — keeps the comment scannable.
                lines.append(f"  - _e.g._ {md_code(s.evidence[0])}")
        return "\n".join(lines)

    def _instance_bullets() -> str:
        if not diff.new_instances:
            return "_none_"
        lines = []
        for snap, labels in sorted(diff.new_instances, key=lambda t: (_SEVERITY_RANK.get(t[0].severity, 3), t[0].title)):
            lines.append(f"- **[{snap.severity.upper()}]** {md_text(snap.title)} — {len(labels)} new instance(s)")
            lines.extend(f"  - {md_code(label)}" for label in labels[:10])
            if len(labels) > 10:
                lines.append(f"  - +{len(labels) - 10} more")
        return "\n".join(lines)

    parts = [
        f"# {title}",
        "",
        (
            f"**{counts['new']} new** · "
            f"**{counts['new_instances']} new instance(s) of existing findings** · "
            f"**{counts['persisted']} persisted** · "
            f"**{counts['resolved']} resolved** · "
            f"**{counts['newly_suppressed']} newly suppressed**"
        ),
        "",
        "## New findings",
        _bullets(diff.new),
        "",
        "## New instances of existing findings",
        _instance_bullets(),
        "",
        "## Resolved findings",
        _bullets(diff.resolved),
        "",
        "## Newly suppressed findings",
        _bullets(diff.newly_suppressed),
        "",
        "## Persisted findings",
        _bullets(diff.persisted),
    ]
    if diff.baseline_without_instances:
        parts += [
            "",
            "_The baseline predates per-instance fingerprints, so new instances of "
            "existing findings can't be detected until it is regenerated._",
        ]
    return "\n".join(parts) + "\n"


__all__ = [
    "DiffReport",
    "FindingSnapshot",
    "diff_findings",
    "finding_id",
    "load_baseline",
    "render_diff_markdown",
]
