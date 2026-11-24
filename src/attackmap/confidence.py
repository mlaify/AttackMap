"""One confidence scale for every finding (#198, docs/confidence.md).

- **high**: the evidence shows the weakness itself, such as a traced
  request-to-sink flow, a literal insecure setting, or a verified pattern.
- **medium**: a strong signal with one unverified link, such as a sink reached
  without a traced source, or a structural match whose context wasn't read.
- **low**: a lead for a human, such as a speculative recall reach, a
  business-logic heuristic, a documented default inferred rather than read,
  or a weak signal.

Detectors set confidence on that scale; :func:`normalize_confidence` enforces
the cross-cutting rules, and ``analyze --min-confidence`` filters on it.
"""

from __future__ import annotations

from .models import Finding

CONFIDENCE_LEVELS: tuple[str, ...] = ("low", "medium", "high")
_RANK = {level: i for i, level in enumerate(CONFIDENCE_LEVELS)}
# Tags that make a finding a lead, whatever the detector said.
_LEAD_TAGS = frozenset({"speculative", "needs-review", "weak-signal"})


def normalize_confidence(findings: list[Finding]) -> None:
    """Speculative, needs-review and weak-signal findings are ``low``."""
    for finding in findings:
        if _LEAD_TAGS & set(finding.tags):
            finding.confidence = "low"


def filter_by_confidence(findings: list[Finding], minimum: str) -> tuple[list[Finding], int]:
    """The findings at or above ``minimum``, and how many were dropped."""
    floor = _RANK[minimum]
    kept = [f for f in findings if _RANK[f.confidence] >= floor]
    return kept, len(findings) - len(kept)


__all__ = ["CONFIDENCE_LEVELS", "filter_by_confidence", "normalize_confidence"]
