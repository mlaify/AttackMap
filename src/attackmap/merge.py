"""Centralized merge behavior for analyzer outputs.

This module is the single source of truth for **how** analyzer-emitted
signals are combined into a single ScanResult. It is loaded by both the
public `merge_analyzer_results` (whole-repo analyzers) and the internal
`merge_analyzer_signals` (file-by-file built-in micro-analyzers).

A new structured signal type is added in one place: append a row to
:data:`MERGE_SCHEMA` describing the field name and its dedup key. All
merge / dedup behavior follows automatically.

## Merge rules

- **Deterministic ordering**: first-seen wins. The order signals appear
  in the merged result is the order they first appeared across the input
  results, walked in input order. We do not reorder.
- **Deduplication**: each list field has a stable key extracted from the
  signal itself (e.g. `(path, method, file)` for routes). Two signals
  that hash to the same key are treated as duplicates; only the first is
  kept.
- **`languages`**: union, then sorted alphabetically for stable display.
- **`files_scanned`**: summed across results.
- **`root`**: taken from the explicit `root` argument when supplied,
  otherwise from the first result.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MergeRule:
    """How one list field on `ScanResult` is merged across analyzer outputs.

    - `attr`: the attribute name on `ScanResult` (e.g. `"routes"`).
    - `key`: a callable that returns a hashable dedup key for one signal.
    """

    attr: str
    key: Callable[[Any], tuple]

    def __post_init__(self) -> None:
        if not self.attr.isidentifier():
            raise ValueError(f"MergeRule.attr must be a valid identifier, got {self.attr!r}")


# The complete schema of list fields on `ScanResult` that get merged
# across analyzer outputs. Order is preserved in the merged result;
# duplicates (by key) are suppressed.
MERGE_SCHEMA: tuple[MergeRule, ...] = (
    MergeRule("routes", lambda item: (item.path, item.method, item.file)),
    MergeRule("external_calls", lambda item: (item.target, item.file)),
    MergeRule("databases", lambda item: (item.kind, item.file)),
    MergeRule("auth_hints", lambda item: (item.hint, item.file)),
    MergeRule("service_hints", lambda item: (item.hint, item.file)),
    MergeRule("edge_hints", lambda item: (item.hint, item.file)),
    MergeRule("entrypoint_hints", lambda item: (item.hint, item.file)),
    MergeRule("protocol_hints", lambda item: (item.hint, item.file)),
    MergeRule("framework_hints", lambda item: (item.hint, item.file)),
    MergeRule("secret_hints", lambda item: (item.name, item.file)),
)


def merge_into(destination: Any, items: Iterable[Any], rule: MergeRule, seen: set) -> None:
    """Append `items` onto `destination.<rule.attr>` deduping against `seen`.

    `seen` is mutated to include the keys of items that were appended.
    Pre-populate `seen` with keys from the existing destination if you
    want to merge across multiple sources without rescanning the list.
    """
    target = getattr(destination, rule.attr)
    for item in items:
        k = rule.key(item)
        if k in seen:
            continue
        seen.add(k)
        target.append(item)


def initial_seen(destination: Any, rule: MergeRule) -> set:
    """Compute the `seen` set for items already on `destination.<rule.attr>`.

    Used by callers that merge into a non-empty destination.
    """
    return {rule.key(item) for item in getattr(destination, rule.attr)}


__all__ = ["MergeRule", "MERGE_SCHEMA", "merge_into", "initial_seen"]
