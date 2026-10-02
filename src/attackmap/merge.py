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
  results, walked in input order. We do not reorder. Analyzers run in
  ``(metadata.priority, name)`` order (#221), so on a duplicate key the
  lower-priority-number analyzer's signal wins.
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
    # Optional: called as `upgrade(existing, duplicate)` when a later signal
    # hashes to an existing key, to fold in information the first one lacked.
    upgrade: Callable[[Any, Any], None] | None = None

    def __post_init__(self) -> None:
        if not self.attr.isidentifier():
            raise ValueError(f"MergeRule.attr must be a valid identifier, got {self.attr!r}")


# The complete schema of list fields on `ScanResult` that get merged
# across analyzer outputs. Order is preserved in the merged result;
# duplicates (by key) are suppressed.

def _upgrade_route_auth(existing: Any, duplicate: Any) -> None:
    """Known route auth beats unknown (#256): first-seen still wins the route,
    but a later analyzer that resolved the guard fills it in."""
    if getattr(existing, "auth", "unknown") == "unknown" and getattr(duplicate, "auth", "unknown") != "unknown":
        existing.auth = duplicate.auth
        existing.guards = list(duplicate.guards)
        existing.guard_evidence = duplicate.guard_evidence

MERGE_SCHEMA: tuple[MergeRule, ...] = (
    MergeRule("routes", lambda item: (item.path, item.method, item.file), upgrade=_upgrade_route_auth),
    # Method is part of the identity (#146b): two verbs on the same target in one
    # file (GET + POST /items) are distinct calls, not duplicates — collapsing
    # them would drop a method before cross-repo contract linking runs.
    MergeRule("external_calls", lambda item: (item.target, item.method, item.file)),
    MergeRule("databases", lambda item: (item.kind, item.file)),
    MergeRule("auth_hints", lambda item: (item.hint, item.file)),
    MergeRule("service_hints", lambda item: (item.hint, item.file)),
    MergeRule("edge_hints", lambda item: (item.hint, item.file)),
    MergeRule("entrypoint_hints", lambda item: (item.hint, item.file)),
    MergeRule("protocol_hints", lambda item: (item.hint, item.file)),
    MergeRule("framework_hints", lambda item: (item.hint, item.file)),
    # Line is part of the identity: redacted names only keep a 4-char prefix
    # (#235), so two different `AKIA…` keys in one file must stay distinct.
    MergeRule("secret_hints", lambda item: (item.name, item.file, item.line)),
    MergeRule(
        "taint_chains",
        lambda item: (
            item.route_method,
            item.route_path,
            item.route_file,
            item.sink_kind,
            item.sink_file,
            item.sink_line,
        ),
    ),
    MergeRule(
        "dependencies",
        lambda item: (item.ecosystem, item.name, item.version, item.file, item.dev),
    ),
    MergeRule(
        "vulnerabilities",
        lambda item: (item.ecosystem, item.package_name, item.package_version, item.id),
    ),
    MergeRule(
        "authz_candidates",
        lambda item: (item.route_method, item.route_path, item.route_file, item.id_param),
    ),
    MergeRule(
        "crypto_weaknesses",
        lambda item: (item.kind, item.file, item.line),
    ),
    MergeRule(
        "web_hardening_issues",
        lambda item: (item.kind, item.file, item.line),
    ),
    MergeRule(
        "code_weaknesses",
        lambda item: (item.kind, item.file, item.line),
    ),
    MergeRule(
        "workflow_issues",
        lambda item: (item.kind, item.file, item.line, item.context),
    ),
    MergeRule(
        "anomalies",
        lambda item: (item.kind, item.route_method, item.route_path, item.route_file),
    ),
)


def merge_into(destination: Any, items: Iterable[Any], rule: MergeRule, seen: set) -> None:
    """Append `items` onto `destination.<rule.attr>` deduping against `seen`.

    `seen` is mutated to include the keys of items that were appended.
    Pre-populate `seen` with keys from the existing destination if you
    want to merge across multiple sources without rescanning the list.
    """
    target = getattr(destination, rule.attr)
    index: dict | None = None
    for item in items:
        k = rule.key(item)
        if k in seen:
            if rule.upgrade is not None:
                if index is None:
                    index = {rule.key(existing): existing for existing in target}
                existing = index.get(k)
                if existing is not None:
                    rule.upgrade(existing, item)
            continue
        seen.add(k)
        target.append(item)
        if index is not None:
            index[k] = item


def initial_seen(destination: Any, rule: MergeRule) -> set:
    """Compute the `seen` set for items already on `destination.<rule.attr>`.

    Used by callers that merge into a non-empty destination.
    """
    return {rule.key(item) for item in getattr(destination, rule.attr)}


__all__ = ["MergeRule", "MERGE_SCHEMA", "merge_into", "initial_seen"]
