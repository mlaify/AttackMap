"""Cross-boundary trust analysis — cross-repo phase 3 (#146c).

The confused-deputy shape at a service seam: repo A forwards data across a link
to repo B (#146b), and B trusts that input — flowing it into a dangerous sink or
an unguarded object access — *because* it arrives from an internal caller rather
than a browser. Each repo looks locally fine: A is "just a client", B "only
serves internal traffic". The bug lives in the gap between them.

This pass rides the contract links and reuses each repo's already-computed
per-repo signals — no new scanning:

- **taint basis**: the linked server route reaches an unsanitized dangerous sink
  (a `TaintChain` on that route) — B pipes the caller's value into SQL/exec/etc.
- **bola basis**: the linked server route is a BOLA/IDOR candidate (an id-bearing
  object access with no ownership check) — B reads/writes the object the caller
  names without checking who is asking.

Findings are **speculative**: cross-repo trust is a judgement call (B may
validate in a way the heuristics miss, or the caller may pre-authorize), so they
are leads for the #147 verifier to adjudicate, not asserted vulnerabilities.
Each cites *both* sides — the caller's call site and the callee's sink/route.

Pure and deterministic: takes the links plus `(repo_id, ScanResult)` primitives.
"""

from __future__ import annotations

from dataclasses import dataclass

from .anomalies import _is_outlier_split
from .contracts import ContractLink, route_template
from .models import Route, ScanResult, TaintChain
from .srcpaths import is_test_file

# Sink kinds whose reach from a caller-supplied value is a real cross-boundary
# risk, split by severity to mirror the single-repo taint policy: injection /
# code-exec / deserialization / template are HIGH; SSRF, NoSQL and a dynamic
# file open are MEDIUM (narrower or lower-impact). `sql_execute` is HIGH — across
# a trust boundary a raw query on caller-supplied data is the classic injection.
_HIGH_SINKS = frozenset(
    {"sql_execute", "subprocess_shell", "eval", "exec", "unsafe_deserialization", "ssti"}
)
_MEDIUM_SINKS = frozenset({"ssrf", "nosql_injection", "dynamic_open"})
_DANGEROUS_SINKS = _HIGH_SINKS | _MEDIUM_SINKS

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# One notch down, for the recall-speculative downgrade.
_LOWER = {"high": "medium", "medium": "low", "low": "low"}


@dataclass(frozen=True)
class CrossBoundaryFlow:
    """A confused-deputy flow across a client→server seam."""

    client_repo: str
    server_repo: str
    method: str
    route: str  # the server route the caller reaches
    basis: str  # "taint" | "bola"
    detail: str  # what B does with the trusted value (sink kind / object access)
    client_target: str
    client_file: str
    client_line: int | None
    server_file: str
    server_line: int | None
    severity: str  # "high" | "medium"


def _route_taint(scan: ScanResult, route: str, method: str) -> TaintChain | None:
    """The most-direct unsanitized dangerous sink the given server route reaches."""
    candidates = [
        c
        for c in scan.taint_chains
        if c.route_path == route
        and not c.sanitized
        and c.sink_kind in _DANGEROUS_SINKS
        and _method_ok(method, c.route_method)
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda c: (c.hops, -c.confidence))


def _route_bola(scan: ScanResult, route: str, method: str):
    for cand in scan.authz_candidates:
        if (
            cand.route_path == route
            and not cand.has_ownership_check
            and cand.reaches_db
            # Only a path-param object id is provably the value the caller
            # supplies via the matched path template — a query/rpc/graphql id
            # can't be tied to the client call from path matching alone.
            and cand.surface == "path_param"
            and _method_ok(method, cand.route_method)
        ):
            return cand
    return None


def _carries_path_value(link: ContractLink) -> bool:
    """True when the client forwards a per-request value in the path — the link
    template has a dynamic (`*`) segment. A fully-static call (e.g. a bare
    `/orders` collection) forwards no id, so it can't be a confused-deputy on
    one, even if the server independently taints a query/body value."""
    return "*" in link.path_template.split("/")


def _taint_severity(chain: TaintChain) -> str:
    sev = "high" if chain.sink_kind in _HIGH_SINKS else "medium"
    # Recall-surfaced chains (#148a) are unconfirmed reach — dock a notch.
    return _LOWER[sev] if chain.speculative else sev


def _bola_severity(method: str) -> str:
    # Read-only object reads are medium; state-changing access is high (matches
    # the single-repo BOLA policy).
    return "high" if (method or "").upper() in _WRITE_METHODS else "medium"


def _method_ok(link_method: str, signal_method: str) -> bool:
    lm, sm = (link_method or "ANY").upper(), (signal_method or "ANY").upper()
    return lm in {"", "ANY"} or sm in {"", "ANY"} or lm == sm


def find_cross_boundary_flows(
    links: list[ContractLink], repo_scans: list[tuple[str, ScanResult]]
) -> list[CrossBoundaryFlow]:
    """Return confused-deputy flows: a linked server route that trusts the
    caller's value into a dangerous sink (taint) or an unguarded object access
    (bola). Deterministic; deduped on the flow identity."""
    scan_by_repo = dict(repo_scans)
    flows: list[CrossBoundaryFlow] = []
    seen: set[tuple] = set()
    for link in links:
        server_scan = scan_by_repo.get(link.server_repo)
        if server_scan is None:
            continue
        # Provenance gate: the caller must actually forward a path value that the
        # callee's path-based signal consumes — otherwise the "the caller's value
        # reaches the sink" claim is unfounded (a static call + an independent
        # server-side query/body taint is not a confused-deputy).
        if not _carries_path_value(link):
            continue

        chain = _route_taint(server_scan, link.server_route_path, link.method)
        bola = _route_bola(server_scan, link.server_route_path, link.method)
        if chain is None and bola is None:
            continue

        if chain is not None:
            basis, detail = "taint", chain.sink_kind
            server_file, server_line = chain.sink_file, chain.sink_line
            severity = _taint_severity(chain)
        else:
            basis, detail = "bola", f"object access on `{bola.id_param}`"
            server_file, server_line = bola.route_file, bola.route_line
            severity = _bola_severity(link.method)

        key = (link.client_repo, link.server_repo, link.method, link.server_route_path, basis)
        if key in seen:
            continue
        seen.add(key)
        flows.append(
            CrossBoundaryFlow(
                client_repo=link.client_repo,
                server_repo=link.server_repo,
                method=link.method,
                route=link.server_route_path,
                basis=basis,
                detail=detail,
                client_target=link.client_target,
                client_file=link.client_file,
                client_line=link.client_line,
                server_file=server_file,
                server_line=server_line,
                severity=severity,
            )
        )
    flows.sort(key=lambda f: (f.client_repo, f.server_repo, f.route, f.basis))
    return flows


# ---------------------------------------------------------------------------
# Trust-assumption gap + cross-repo anomaly (#146d / #149b)
# ---------------------------------------------------------------------------

# repo_id -> {(route file, method, path): has_auth_signal}
AuthByRepo = dict


@dataclass(frozen=True)
class TrustGap:
    """A mutual-trust gap: repo A makes a state-changing call across a link to a
    route repo B serves with no authentication/authorization control. If A
    assumes B enforces and B assumes only trusted callers reach it, nobody
    does — the action is effectively unauthenticated across the boundary."""

    client_repo: str
    server_repo: str
    method: str
    route: str
    client_target: str
    client_file: str
    client_line: int | None
    server_file: str
    server_line: int | None
    severity: str = "high"


@dataclass(frozen=True)
class CrossRepoAnomaly:
    """The sibling service that omits a control its peers enforce (#149b): the
    fleet-level odd-one-out. Among repos serving the same resource route, a
    strong majority guard it and this one doesn't."""

    repo: str
    method: str
    route: str
    template: str
    peers: tuple[str, ...]  # sibling repos that DO enforce auth on this route
    severity: str = "medium"


def _matching_route(scan: ScanResult, link: ContractLink) -> Route | None:
    for r in scan.routes:
        if (
            r.path == link.server_route_path
            and r.file == link.server_file
            and _method_ok(link.method, r.method)
        ):
            return r
    return None


def find_trust_gaps(
    links: list[ContractLink],
    repo_scans: list[tuple[str, ScanResult]],
    auth_by_repo: AuthByRepo,
) -> list[TrustGap]:
    """State-changing cross-repo calls landing on a server route with no auth
    control. Deterministic; deduped. Speculative — the route may be protected by
    a mechanism the marker heuristics miss (a gateway, mTLS), so these are leads
    for the verifier, not asserted vulnerabilities."""
    scan_by_repo = dict(repo_scans)
    out: list[TrustGap] = []
    seen: set[tuple] = set()
    for link in links:
        server = scan_by_repo.get(link.server_repo)
        if server is None:
            continue
        route = _matching_route(server, link)
        if route is None:
            continue
        # Only state-changing actions — a public read is commonly intentional,
        # so requiring a write keeps this to the high-signal "unauth mutation".
        # When the server route is method-unspecified (`ANY`, e.g. an XRPC
        # surface), fall back to the caller's concrete verb so a known POST/PUT/
        # PATCH/DELETE call still counts.
        route_method = (route.method or "ANY").upper()
        client_method = (link.client_method or "").upper()
        if route_method in _WRITE_METHODS:
            verb = route_method
        elif route_method in {"", "ANY"} and client_method in _WRITE_METHODS:
            verb = client_method
        else:
            continue
        amap = auth_by_repo.get(link.server_repo, {})
        # Default True (assume protected) when unknown — never over-fire on a
        # route we couldn't read.
        if amap.get((route.file, route.method, route.path), True):
            continue
        key = (link.client_repo, link.server_repo, route.method, route.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            TrustGap(
                client_repo=link.client_repo,
                server_repo=link.server_repo,
                method=verb,
                route=route.path,
                client_target=link.client_target,
                client_file=link.client_file,
                client_line=link.client_line,
                server_file=route.file,
                server_line=route.line,
            )
        )
    out.sort(key=lambda g: (g.client_repo, g.server_repo, g.route))
    return out


def find_cross_repo_anomalies(
    repo_scans: list[tuple[str, ScanResult]], auth_by_repo: AuthByRepo
) -> list[CrossRepoAnomaly]:
    """The fleet-level odd-one-out (#149b): among repos serving the same resource
    route, flag the one that omits an auth control its siblings enforce. A repo
    "enforces" a template when every route it serves under that template carries
    an auth signal. Requires a cohort of ≥3 repos and a strong-majority split, so
    a genuinely-split surface isn't nagged. Speculative."""
    # (template, method) -> repo -> list[has_auth] ; a representative route per
    # (template, method, repo). Method is part of the cohort key so a GET and a
    # POST on the same path aren't treated as the same route (they aren't).
    cohort: dict[tuple[str, str], dict[str, list[bool]]] = {}
    example: dict[tuple[str, str, str], Route] = {}
    for repo, scan in repo_scans:
        amap = auth_by_repo.get(repo, {})
        for r in scan.routes:
            if is_test_file(r.file):
                continue
            template = route_template(r.path)
            if template is None:
                continue
            key = (template, (r.method or "ANY").upper())
            authed = amap.get((r.file, r.method, r.path), False)
            cohort.setdefault(key, {}).setdefault(repo, []).append(authed)
            example.setdefault((*key, repo), r)

    out: list[CrossRepoAnomaly] = []
    for (template, method), by_repo in cohort.items():
        if len(by_repo) < 3:  # need enough siblings to establish a norm
            continue
        enforcing = {repo for repo, flags in by_repo.items() if all(flags)}
        omitting = sorted(set(by_repo) - enforcing)
        if not _is_outlier_split(len(enforcing), len(omitting), len(by_repo)):
            continue
        peers = tuple(sorted(enforcing))
        for repo in omitting:
            r = example[(template, method, repo)]
            out.append(
                CrossRepoAnomaly(
                    repo=repo,
                    method=method,
                    route=r.path,
                    template=template,
                    peers=peers,
                )
            )
    out.sort(key=lambda a: (a.template, a.method, a.repo))
    return out


__all__ = [
    "CrossBoundaryFlow",
    "CrossRepoAnomaly",
    "TrustGap",
    "find_cross_boundary_flows",
    "find_cross_repo_anomalies",
    "find_trust_gaps",
]
