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
- **Route twins** (#337): a plugin route on the same `(file, line)` as a
  built-in route supersedes it when they are plausibly one registration
  (the plugin joined a group prefix the built-in couldn't see). See
  :func:`superseded_builtin_routes`.
- **`languages`**: union, then sorted alphabetically for stable display.
- **`files_scanned`**: summed across results.
- **`root`**: taken from the explicit `root` argument when supplied,
  otherwise from the first result.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .models import NATIVE_WEAKNESS_KINDS


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

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_CONFIDENCE_RANK = {"low": 0.3, "medium": 0.6, "high": 0.9}


def _rank(item: Any) -> tuple[int, float]:
    # An unset confidence reads as medium, the same as tiered findings do
    # (threat_model._confidence_value): a report that didn't state one isn't
    # weaker than one that says "low".
    confidence = getattr(item, "confidence", None)
    if confidence is None:
        confidence = _CONFIDENCE_RANK["medium"]
    elif isinstance(confidence, str):
        confidence = _CONFIDENCE_RANK.get(confidence, _CONFIDENCE_RANK["medium"])
    return _SEVERITY_RANK.get(getattr(item, "severity", ""), -1), float(confidence)


def keep_more_severe(existing: Any, duplicate: Any) -> None:
    """Upgrade hook for records with ``severity`` (and optionally a numeric or
    low/medium/high ``confidence``): on a duplicate key keep the more severe,
    then the more confident, report: its severity, confidence, descriptive
    fields and provenance, so the merged record never pairs one analyzer's
    severity with another's evidence or `source_analyzer` (#359)."""
    if _rank(duplicate) > _rank(existing):
        existing.severity = duplicate.severity
        if hasattr(existing, "confidence"):
            existing.confidence = duplicate.confidence
        for name in _UPGRADE_FIELDS:
            value = getattr(duplicate, name, None)
            if value is not None and hasattr(existing, name):
                setattr(existing, name, value)
        for name in _UPGRADE_FIELDS_PAIRED:
            if hasattr(existing, name):
                setattr(existing, name, getattr(duplicate, name, None))


# Fields a winning duplicate carries over (when it sets them).
_UPGRADE_FIELDS = ("evidence_text", "context", "escalation_path", "platform", "source_analyzer")
# Fields that describe the winner's report as a pair and are carried over even
# when unset, so a merged record never pairs one analyzer's severity with
# another analyzer's traced input.
_UPGRADE_FIELDS_PAIRED = ("source_kind", "source_line")


def _upgrade_native_weakness(existing: Any, duplicate: Any) -> None:
    if existing.kind in NATIVE_WEAKNESS_KINDS:
        keep_more_severe(existing, duplicate)


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
    # Native C/C++ kinds (#189) carry evidence in the identity (two sinks of
    # one kind on a line are two instances), and a true duplicate keeps the
    # more severe report with its traced input. Other kinds keep the
    # (kind, file, line) identity and the first report.
    MergeRule(
        "code_weaknesses",
        lambda item: (
            item.kind, item.file, item.line,
            item.evidence_text if item.kind in NATIVE_WEAKNESS_KINDS else None,
        ),
        upgrade=_upgrade_native_weakness,
    ),
    MergeRule(
        "workflow_issues",
        lambda item: (item.kind, item.file, item.line, item.context),
    ),
    MergeRule(
        "supply_chain_issues",
        lambda item: (item.kind, item.file, item.line, item.package),
    ),
    # Evidence is part of the identity: two settings of one kind at one line
    # (a `/var/log` and a `docker.sock` mount) are two instances. On a true
    # duplicate the more severe report wins.
    MergeRule(
        "cloud_misconfigs",
        lambda item: (item.kind, item.file, item.line, item.resource, item.evidence_text),
        upgrade=keep_more_severe,
    ),
    # Evidence is part of the identity: two ATS exceptions in one binary
    # (lineless) Info.plist are two instances. On a true duplicate (the Swift
    # and Objective-C analyzers both reporting a plist) the more severe wins.
    MergeRule(
        "app_surface_issues",
        lambda item: (item.kind, item.file, item.line, item.evidence_text),
        upgrade=keep_more_severe,
    ),
    MergeRule(
        "secret_history",
        lambda item: (item.kind, item.file, item.name, item.introduced_in),
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


# A path parameter in any framework's syntax: `:id`, `{id}` / `{id...}`,
# `<int:id>`, `[id]`. Normalized to one placeholder, so `/users/:id` and
# `/users/{id}` compare equal. Linear: each alternative stops at its closer.
_PATH_PARAM = re.compile(r":[A-Za-z_]\w*|\{[^{}/]*\}|<[^<>/]*>|\[[^\[\]/]*\]")
# Segments of a path considered for suffixes; a longer path only offers its
# last ones (a twin's built-in path is the end of the plugin's).
_MAX_SUFFIX_SEGMENTS = 32


def _route_segments(path: str) -> tuple[str, ...]:
    """A path's segments for twin matching: parameters normalized, empty
    segments (leading, trailing, repeated `/`) dropped. The root is ``()``."""
    return tuple(_PATH_PARAM.sub("{}", seg) for seg in path.strip().split("/") if seg)


def superseded_builtin_routes(builtin_routes: Iterable[Any], plugin_routes: Iterable[Any]) -> set[int]:
    """``id()`` of each built-in route that a plugin route on the same
    (file, line) supersedes (#337).

    Core's built-in extractors read one call at a time; a plugin that joins
    group / router prefixes (`api := r.Group("/api")`) emits the same
    registration under a longer path, and the `(path, method, file)` merge
    key keeps both. A built-in route is a twin of a plugin route on its
    (file, line) when:

    - the plugin path ends with the built-in path at a segment boundary
      (parameters compared as placeholders, so `:id` matches `{id}`), and
    - the methods match, or the built-in said `ANY` (a plugin `ANY` never
      supersedes a specific built-in method: it would lose the method).

    The root `/` is a suffix of every path, so a built-in `/` only matches
    a plugin `/`, or the plugin's one route when the line has exactly one
    route of each kind. Two calls on one line whose paths end the same way
    (`r.Get("/a", h); v1.Get("/a", h)`) can still be taken for one
    registration; that's the residual risk, and it needs two registrations
    of the same path and method on one line.

    Only a built-in route is ever dropped, so two plugin routes, two
    built-in routes, or different registrations on one line all survive.
    Linear: plugin routes are indexed per site by (method, suffix).
    """
    # Per site: {(method, suffix)}, {suffix}, the methods of plugin roots, and
    # the number of plugin routes.
    sites: dict[tuple[str, int], tuple[set, set, set, list[int]]] = {}
    for route in plugin_routes:
        if route.line is None:
            continue
        by_method, any_method, roots, count = sites.setdefault((route.file, route.line), (set(), set(), set(), [0]))
        count[0] += 1
        segments = _route_segments(route.path)
        method = route.method.upper()
        if not segments:
            roots.add(method)
        for start in range(max(0, len(segments) - _MAX_SUFFIX_SEGMENTS), len(segments) + 1):
            suffix = segments[start:]
            by_method.add((method, suffix))
            any_method.add(suffix)
    superseded: set[int] = set()
    if not sites:
        return superseded
    builtins = [route for route in builtin_routes if route.line is not None]
    builtin_count: dict[tuple[str, int], int] = {}
    for route in builtins:
        key = (route.file, route.line)
        builtin_count[key] = builtin_count.get(key, 0) + 1
    for route in builtins:
        site = sites.get((route.file, route.line))
        if site is None:
            continue
        by_method, any_method, roots, count = site
        segments = _route_segments(route.path)
        method = route.method.upper()
        if not segments and not (count[0] == 1 and builtin_count[(route.file, route.line)] == 1):
            # A root only matches a plugin root (`()` is every path's suffix).
            twin = bool(roots) if method == "ANY" else method in roots
        elif method == "ANY":
            twin = segments in any_method
        else:
            twin = (method, segments) in by_method
        if twin:
            superseded.add(id(route))
    return superseded


def initial_seen(destination: Any, rule: MergeRule) -> set:
    """Compute the `seen` set for items already on `destination.<rule.attr>`.

    Used by callers that merge into a non-empty destination.
    """
    return {rule.key(item) for item in getattr(destination, rule.attr)}


__all__ = ["MergeRule", "MERGE_SCHEMA", "keep_more_severe", "merge_into", "initial_seen", "superseded_builtin_routes"]
