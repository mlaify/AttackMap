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

    @classmethod
    def from_finding(cls, f: Finding) -> "FindingSnapshot":
        return cls(
            id=finding_id(f.title),
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            tags=tuple(f.tags),
            evidence=tuple(f.evidence),
        )

    @classmethod
    def from_dump(cls, d: dict[str, Any]) -> "FindingSnapshot":
        title = str(d.get("title", ""))
        return cls(
            id=finding_id(title),
            title=title,
            severity=str(d.get("severity", "medium")),
            confidence=str(d.get("confidence", "medium")),
            tags=tuple(d.get("tags") or ()),
            evidence=tuple(d.get("evidence") or ()),
        )


@dataclass
class DiffReport:
    new: list[FindingSnapshot] = field(default_factory=list)
    persisted: list[FindingSnapshot] = field(default_factory=list)
    resolved: list[FindingSnapshot] = field(default_factory=list)

    @property
    def has_new_high(self) -> bool:
        return any(s.severity == "high" for s in self.new)

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "persisted": len(self.persisted),
            "resolved": len(self.resolved),
        }


def diff_findings(
    baseline: list[FindingSnapshot], current: list[FindingSnapshot]
) -> DiffReport:
    base_ids = {s.id for s in baseline}
    cur_ids = {s.id for s in current}
    return DiffReport(
        new=[s for s in current if s.id not in base_ids],
        persisted=[s for s in current if s.id in base_ids],
        resolved=[s for s in baseline if s.id not in cur_ids],
    )


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
            lines.append(f"- **[{s.severity.upper()}]** {s.title}")
            if s.evidence:
                # First evidence line only — keeps the comment scannable.
                lines.append(f"  - _e.g._ {s.evidence[0]}")
        return "\n".join(lines)

    parts = [
        f"# {title}",
        "",
        (
            f"**{counts['new']} new** · "
            f"**{counts['persisted']} persisted** · "
            f"**{counts['resolved']} resolved**"
        ),
        "",
        "## New findings",
        _bullets(diff.new),
        "",
        "## Resolved findings",
        _bullets(diff.resolved),
        "",
        "## Persisted findings",
        _bullets(diff.persisted),
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
