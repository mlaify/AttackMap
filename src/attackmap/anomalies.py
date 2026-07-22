"""Anomaly / outlier detection — surface the odd-one-out (#78).

The closest honest thing to "find the unknown": instead of matching a
known-bad signature, flag a route that deviates from the norm its own
siblings establish. If a cohort of routes under the same resource prefix
all carry an auth signal and one doesn't, that one is worth a human's
eyes — no CVE, no rule, just an internal inconsistency that often marks a
forgotten decorator or a copy-paste that dropped a guard.

## Heuristics (all peer-group relative)

- **auth_outlier**: siblings carry an auth/authorization signal near the
  handler; this route doesn't. (This is the scan-level, route-cohort
  realization of the layered engine's `asymmetric_protection` /
  `control_strength_mismatch` insight — divergent control strength across
  similar surfaces, promoted to an evidence-cited finding.)
- **validation_outlier**: among a cohort's state-changing handlers, peers
  validate their input and this one shows no validation marker.
- **method_outlier**: a lone state-changing method exposed in a cohort
  that is otherwise read-only.
- **invariant_violation** (#149a): the *mined-invariant* pass. Its cohort is
  not a route-path prefix but the set of handlers that reach the same
  dangerous sink kind (from the taint pass). When a strong majority guard the
  request — an auth or validation check *before* the sink — the pass mines
  that as an implicit invariant and flags the handler that reaches the same
  sink kind with no guard before it, citing the mined rule as evidence. This
  is signature-free: it compares the code against itself, so it can surface a
  forgotten guard on a sink pattern no rule anticipates.

## Precision

Everything is relative to a *consistent* peer group, and confidence
scales with how consistent it is: a lone deviation among many agreeing
siblings is more likely a mistake than the same deviation in a group
that's split. Outliers are only flagged when they're a strict minority,
so a genuinely 50/50 surface isn't nagged. Per-route signal detection
reads a small window around the handler (decorators / middleware /
early-body checks), the same imprecise-but-useful proxy the rest of the
analyzers use — findings are evidence, not proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Anomaly, Route, ScanResult
from .srcpaths import is_test_file

if TYPE_CHECKING:
    from .progress import JsonScanProgress, ScanProgress

    _Progress = ScanProgress | JsonScanProgress


@dataclass
class _SignalCtx:
    """Shared state for per-route signal lookups within one scan."""

    root: Path
    line_cache: dict[str, list[str]]
    file_route_lines: dict[str, list[int]]

# Auth / authorization signal near a handler. Intentionally broad: a false
# *presence* only suppresses an outlier (fewer findings), so recall here
# keeps false positives down. Mirrors authz.py's ownership markers plus
# framework auth decorators / middleware.
_AUTH_MARKERS = re.compile(
    r"""
    login_required | @authenticated | ensureAuthenticated | requireAuth | requiresAuth
    | require[s]?_permission | permission_required | permission_classes | IsAuthenticated
    | current_user | currentUser | \brequest\.user\b | \breq\.user\b | \bctx\.user\b
    | authorize | authoriz | \bpolicy\b | \bpolicies\b | \bguard\b | can_access | canAccess
    | has_access | hasAccess | check_access | verify_owner | assert_owner | ensure_owner
    | is_authorized | isAuthorized | @roles? | requireRole | hasRole | @PreAuthorize
    | @Secured | @RolesAllowed | authenticate\s*\( | ensureLoggedIn | verifyToken
    | verify_jwt | jwt_required | @jwt_required | \bmiddleware\b.*auth | auth.*\bmiddleware\b
    | passport\.authenticate | before_action\s*:?\s*:authenticate | check_authentication
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Input-validation signal near a handler.
_VALIDATION_MARKERS = re.compile(
    r"""
    validate | validation | \bschema\b | pydantic | BaseModel | \bjoi\b | \bzod\b | \byup\b
    | z\.object | Joi\. | \.parse\s*\( | safeParse | serializer | marshmallow | cerberus
    | is_valid\s*\( | \.clean\s*\( | clean_data | sanitize | check_arg | assert_ | expect\s*\(
    | @validate | @Valid | class-validator | express-validator | \bcheck\s*\( | \bbody\s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)

_READ_METHODS = {"GET", "HEAD", "OPTIONS", "ANY"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Path-parameter forms across frameworks (same as authz.py): {id} :id <id>.
_PARAM_SEG_RE = re.compile(r"[{:<]|>$|}$")

# A handler's signal span runs from its route declaration down to the next
# route in the same file (its own body), so one handler's decorator/body
# never bleeds into a sibling's window. Capped so a huge handler doesn't
# swallow the file, and extended upward over contiguous `@decorator` lines
# for the auth-decorator-above-`@route` idiom.
_MAX_SPAN = 40
_DECORATOR_LOOKUP = 6

_MAX_FILE_BYTES = 1_000_000
# A cohort must have at least this many routes to reason about a "norm".
_MIN_GROUP = 3

# Invariant mining (#149a). A sink cohort must have at least this many distinct
# handlers before a "guard the request before the sink" invariant is credible —
# higher than `_MIN_GROUP` because a wrong call here points at a dangerous sink.
_MIN_INVARIANT_COHORT = 4

# Human labels for the taint sink kinds an invariant is mined over (mirrors
# threat_model._TAINT_SINK_LABEL; kept local so anomalies.py stays standalone).
_SINK_LABELS: dict[str, str] = {
    "sql_execute": "database (SQL execute)",
    "subprocess_shell": "command execution",
    "eval": "code eval",
    "exec": "code exec",
    "dynamic_open": "filesystem open",
    "unsafe_deserialization": "unsafe deserialization",
    "ssti": "template injection",
    "ssrf": "outbound request (SSRF)",
    "nosql_injection": "NoSQL query",
    "open_redirect": "redirect target",
}

# Leading segments that are transport scaffolding, not the resource itself
# (`/api`, `/v1`, `/rest`). Stripped so the cohort key lands on the resource
# root — /api/users, /api/users/<id> and /api/users/export all group as
# "api/users" — while versioned resources still separate (api/v1/users vs
# api/v1/orders). `admin`/`internal`/`public` are deliberately NOT here:
# they mark real trust boundaries worth grouping on.
_SCAFFOLD_RE = re.compile(r"^(?:api|rest|graphql|gql|v\d+(?:beta\d*|alpha\d*)?)$", re.IGNORECASE)


def find_anomalies(
    scan: ScanResult,
    root: str | Path | None = None,
    progress: "_Progress | None" = None,
) -> list[Anomaly]:
    """Return within-repo consistency outliers for the routes in ``scan``.

    On a large route surface the per-cohort source-window reads dominate this
    pass, so when a ``progress`` reporter is supplied it drives a determinate
    bar over the cohorts (rather than an open-ended spinner).
    """
    root_path = Path(root or scan.root).resolve()

    routes = [r for r in scan.routes if not is_test_file(r.file)]
    groups: dict[str, list[Route]] = {}
    for route in routes:
        key = _peer_key(route.path)
        if key:
            groups.setdefault(key, []).append(route)

    # Per-file line cache (read each source file at most once) and the sorted
    # set of route lines per file, used to bound each handler's signal span.
    line_cache: dict[str, list[str]] = {}
    file_route_lines: dict[str, list[int]] = {}
    for route in routes:
        if route.line is not None:
            file_route_lines.setdefault(route.file, []).append(route.line)
    for lines in file_route_lines.values():
        lines.sort()

    ctx = _SignalCtx(root_path, line_cache, file_route_lines)

    if progress is not None:
        progress.begin(len(groups), "Anomaly / outlier detection")

    out: list[Anomaly] = []
    for key, members in groups.items():
        if progress is not None:
            progress.advance(key)
        if len(members) < _MIN_GROUP:
            continue
        if not _is_route_like_cohort(key, members):
            continue
        out.extend(_auth_outliers(key, members, ctx))
        out.extend(_method_outliers(key, members))
        out.extend(_validation_outliers(key, members, ctx))

    # Mined-invariant pass (#149a): cohorts of handlers reaching the same
    # dangerous sink, flagged when the majority guard the request before it.
    out.extend(_invariant_violations(scan, ctx))

    out.sort(key=lambda a: (-a.confidence, a.route_file, a.route_path))
    return out


# --- Heuristics ------------------------------------------------------------


def _auth_outliers(key: str, members: list[Route], ctx: _SignalCtx) -> list[Anomaly]:
    with_auth: list[Route] = []
    without_auth: list[Route] = []
    for route in members:
        if _route_has_signal(route, ctx, _AUTH_MARKERS):
            with_auth.append(route)
        else:
            without_auth.append(route)

    if not _is_outlier_split(len(with_auth), len(without_auth), len(members)):
        return []

    examples = _peer_examples(with_auth)
    return [
        Anomaly(
            kind="auth_outlier",
            route_path=r.path,
            route_method=r.method,
            route_file=r.file,
            route_line=r.line,
            peer_group=key,
            peer_group_size=len(members),
            consistent_peers=len(with_auth),
            deviation=(
                f"{len(with_auth)} of {len(members)} routes under '{key}' carry an "
                f"auth/authorization signal near the handler; this one does not"
            ),
            peer_examples=examples,
            severity="high",
            confidence=_confidence(len(with_auth)),
            source_analyzer="anomalies",
        )
        for r in without_auth
    ]


def _validation_outliers(key: str, members: list[Route], ctx: _SignalCtx) -> list[Anomaly]:
    # Validation only meaningfully applies to state-changing handlers.
    writers = [r for r in members if r.method.upper() in _WRITE_METHODS]
    if len(writers) < _MIN_GROUP:
        return []
    with_val: list[Route] = []
    without_val: list[Route] = []
    for route in writers:
        if _route_has_signal(route, ctx, _VALIDATION_MARKERS):
            with_val.append(route)
        else:
            without_val.append(route)

    if not _is_outlier_split(len(with_val), len(without_val), len(writers)):
        return []

    examples = _peer_examples(with_val)
    return [
        Anomaly(
            kind="validation_outlier",
            route_path=r.path,
            route_method=r.method,
            route_file=r.file,
            route_line=r.line,
            peer_group=key,
            peer_group_size=len(writers),
            consistent_peers=len(with_val),
            deviation=(
                f"{len(with_val)} of {len(writers)} state-changing routes under '{key}' "
                f"validate their input; this one shows no validation marker"
            ),
            peer_examples=examples,
            severity="low",
            # Validation detection is noisier than auth — cap the ceiling.
            confidence=min(0.7, _confidence(len(with_val))),
            source_analyzer="anomalies",
        )
        for r in without_val
    ]


def _method_outliers(key: str, members: list[Route]) -> list[Anomaly]:
    readers = [r for r in members if r.method.upper() in _READ_METHODS]
    writers = [r for r in members if r.method.upper() in _WRITE_METHODS]
    # A lone writer in a cohort that is otherwise a solid read-only cluster.
    # Require a large read-only majority — one POST among a few GETs is just
    # ordinary CRUD, so only a dominant read cluster makes the writer odd.
    if len(writers) != 1 or len(readers) < 4:
        return []
    r = writers[0]
    return [
        Anomaly(
            kind="method_outlier",
            route_path=r.path,
            route_method=r.method,
            route_file=r.file,
            route_line=r.line,
            peer_group=key,
            peer_group_size=len(members),
            consistent_peers=len(readers),
            deviation=(
                f"{len(readers)} of {len(members)} routes under '{key}' are read-only; "
                f"this {r.method} is the only state-changing method in the cohort"
            ),
            peer_examples=_peer_examples(readers),
            severity="medium",
            confidence=min(0.7, _confidence(len(readers))),
            source_analyzer="anomalies",
        )
    ]


# --- Mined-invariant pass (#149a) ------------------------------------------


def _invariant_violations(scan: ScanResult, ctx: _SignalCtx) -> list[Anomaly]:
    """Mine a "guard the request before the sink" invariant per sink kind and
    flag the handler that violates it.

    The cohort is not a route-path prefix but the set of handlers that reach
    the *same dangerous sink kind* (from ``scan.taint_chains``). When a strong
    majority of those handlers apply an auth/validation guard before the sink,
    that pattern is mined as an implicit invariant and every cohort member that
    reaches the same sink kind with no preceding guard is flagged, citing the
    mined rule. Signature-free: the code is measured against its own norm.

    Sanitized chains (#137) are excluded — a sink-local neutralizer is a
    different control from a handler guard, and dropping them keeps the cohort
    (and any violator) to genuinely undefended flows, which is the precise set.
    """
    # Route lookup, keyed by the identity a taint chain carries. Line-less
    # routes are skipped: without a declaration line the handler span (and so
    # "before the sink") can't be bounded, and precision matters more than the
    # marginal recall here.
    route_by_key: dict[tuple[str, str, str], Route] = {}
    for route in scan.routes:
        if is_test_file(route.file) or route.line is None:
            continue
        route_by_key.setdefault((route.file, route.method, route.path), route)

    # sink_kind -> { route_key -> (route, [chains to this kind]) }
    per_kind: dict[str, dict[tuple[str, str, str], tuple[Route, list]]] = {}
    for chain in scan.taint_chains:
        if chain.sanitized:
            continue
        if is_test_file(chain.route_file) or is_test_file(chain.sink_file):
            continue
        key = (chain.route_file, chain.route_method, chain.route_path)
        route = route_by_key.get(key)
        if route is None:
            continue
        cohort = per_kind.setdefault(chain.sink_kind, {})
        _, chains = cohort.setdefault(key, (route, []))
        chains.append(chain)

    out: list[Anomaly] = []
    for kind, cohort in per_kind.items():
        members = list(cohort.values())
        if len(members) < _MIN_INVARIANT_COHORT:
            continue
        guarded: list[Route] = []
        unguarded: list[Route] = []
        for route, chains in members:
            if all(_guard_before_sink(route, c.sink_file, c.sink_line, ctx) for c in chains):
                guarded.append(route)
            else:
                unguarded.append(route)
        if not _is_outlier_split(len(guarded), len(unguarded), len(members)):
            continue
        label = _SINK_LABELS.get(kind, kind)
        invariant = (
            f"{len(guarded)} of {len(members)} handlers that reach a {label} sink "
            f"apply an auth/validation guard before it"
        )
        examples = _peer_examples(guarded)
        for route in unguarded:
            out.append(
                Anomaly(
                    kind="invariant_violation",
                    route_path=route.path,
                    route_method=route.method,
                    route_file=route.file,
                    route_line=route.line,
                    peer_group=f"sink:{kind}",
                    peer_group_size=len(members),
                    consistent_peers=len(guarded),
                    deviation=(
                        f"reaches a {label} sink with no auth/validation guard "
                        f"before it, unlike its sibling handlers"
                    ),
                    invariant=invariant,
                    peer_examples=examples,
                    severity="high",
                    confidence=_confidence(len(guarded)),
                    source_analyzer="anomalies",
                )
            )
    return out


def _guard_before_sink(
    route: Route, sink_file: str, sink_line: int | None, ctx: _SignalCtx
) -> bool:
    """True if an auth/validation marker guards the handler *before* it reaches
    the sink.

    When the sink lands inside the handler's own span, the marker must appear
    strictly above the sink line — a guard placed after the sink doesn't defend
    it. When the sink is elsewhere (a downstream file, or — because the import
    walk fans a route out to every sink in its file — another handler's body),
    the ordering test doesn't apply: an entry guard anywhere in this handler's
    span precedes the reach to that sink by construction, so the whole span
    counts.
    """
    lines = _file_lines(route.file, ctx)
    if not lines or route.line is None:
        return False
    start, end = _span_bounds(route, lines, ctx.file_route_lines.get(route.file, []))
    # sink_line is 1-based; index sink_line-1 is the sink itself. Only tighten
    # the window to "before the sink" when the sink sits within this span.
    if sink_file == route.file and sink_line is not None and start < sink_line - 1 < end:
        end = sink_line - 1
    if end <= start:
        return False
    window = "\n".join(lines[start:end])
    return (
        _AUTH_MARKERS.search(window) is not None
        or _VALIDATION_MARKERS.search(window) is not None
    )


# --- Internals -------------------------------------------------------------


def _is_route_like_cohort(key: str, members: list[Route]) -> bool:
    """Reject cohorts that are route-extractor noise rather than a real
    resource surface.

    Method-call strings the extractor mistakes for routes (``headers.delete
    ('content-type')`` → ``DELETE /content-type``, ``params.get('request_uri')``
    → ``GET /request_uri``) collapse to a single bare path repeated across
    files. A genuine resource cohort instead has *structural variety*: more
    than one distinct path, and at least one member that carries a path
    parameter or descends below the cohort key. Requiring both keeps real
    surfaces (``/api/users`` + ``/api/users/{id}``) while dropping the noise.
    """
    distinct_paths = {r.path for r in members}
    if len(distinct_paths) < 2:
        return False
    key_depth = key.count("/") + 1
    for path in distinct_paths:
        if _PARAM_SEG_RE.search(path):
            return True
        if len([s for s in path.split("/") if s]) > key_depth:
            return True
    return False


def _is_outlier_split(consistent: int, deviating: int, total: int) -> bool:
    """True when ``deviating`` routes are a strict, small minority against a
    consistent majority — the shape of a real odd-one-out."""
    if consistent < 2 or deviating < 1:
        return False
    # Outliers may be at most a quarter of the cohort (min 1), so a split
    # group isn't nagged and a large consistent group can tolerate a couple.
    return deviating <= max(1, total // 4)


def _confidence(consistent_peers: int) -> float:
    """Scale confidence with the size of the agreeing peer group."""
    return round(min(0.9, 0.45 + 0.09 * consistent_peers), 2)


def _peer_key(path: str) -> str | None:
    """Cohort key: scaffolding prefix (``api``/version) plus the resource
    root — the first static segment past the scaffolding. ``None`` if there
    is no static prefix (e.g. ``/{id}``), which has no resource cohort.

    Examples: ``/api/users/{id}`` → ``api/users``; ``/api/users/export`` →
    ``api/users``; ``/api/v1/orders/{id}`` → ``api/v1/orders``."""
    static: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if _PARAM_SEG_RE.search(seg):
            break
        static.append(seg)
    if not static:
        return None
    i = 0
    while i < len(static) and _SCAFFOLD_RE.match(static[i]):
        i += 1
    # scaffolding + the resource root (or just the scaffolding if the whole
    # static prefix was scaffolding, e.g. a bare `/api`).
    key_parts = static[: i + 1] if i < len(static) else static
    return "/".join(key_parts) or None


def _peer_examples(routes: list[Route], limit: int = 3) -> list[str]:
    seen: list[str] = []
    for r in routes:
        label = f"{r.method} {r.path}"
        if label not in seen:
            seen.append(label)
        if len(seen) >= limit:
            break
    return seen


def _route_has_signal(route: Route, ctx: _SignalCtx, marker: re.Pattern[str]) -> bool:
    """True if ``marker`` appears within the route handler's own span.

    The span is the handler's line range — from its declaration (extended
    upward over contiguous ``@decorator`` lines) down to just before the
    next route in the same file — so a sibling handler's guard is never
    mistaken for this one's. With no line info, fall back to the whole file."""
    lines = _file_lines(route.file, ctx)
    if not lines:
        return False
    if route.line is None:
        return marker.search("\n".join(lines)) is not None
    start, end = _span_bounds(route, lines, ctx.file_route_lines.get(route.file, []))
    return marker.search("\n".join(lines[start:end])) is not None


def _span_bounds(route: Route, lines: list[str], route_lines: list[int]) -> tuple[int, int]:
    """Return the 0-based [start, end) slice of ``lines`` owned by ``route``."""
    assert route.line is not None
    idx = route.line - 1  # 0-based route declaration line
    # End at the next route declaration in the file (its decorators/body
    # belong to it), capped so a huge handler can't swallow the file.
    next_line = next((ln for ln in route_lines if ln > route.line), None)
    end = min(len(lines), route.line - 1 + _MAX_SPAN)
    if next_line is not None:
        end = min(end, next_line - 1)
    # Extend upward over contiguous decorator lines (auth decorator placed
    # above the @route decorator), but not past the previous route.
    prev_line = next((ln for ln in reversed(route_lines) if ln < route.line), 0)
    start = idx
    limit = max(prev_line, idx - _DECORATOR_LOOKUP)
    while start - 1 >= limit and lines[start - 1].lstrip().startswith("@"):
        start -= 1
    return max(0, start), max(start + 1, end)


def _file_lines(rel_file: str, ctx: _SignalCtx) -> list[str]:
    if rel_file in ctx.line_cache:
        return ctx.line_cache[rel_file]
    path = ctx.root / rel_file
    lines: list[str] = []
    try:
        if path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except (OSError, ValueError):
        lines = []
    ctx.line_cache[rel_file] = lines
    return lines


__all__ = ["find_anomalies"]
