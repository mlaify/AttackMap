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

from .contracts import ContractLink
from .models import ScanResult, TaintChain

# Sink kinds whose reach from a caller-supplied value is a real cross-boundary
# risk. (Same dangerous set the single-repo taint findings surface; the
# feeds-attack-path-only kinds like `sql_execute`/`dynamic_open` are included
# here because across a trust boundary they are the classic confused-deputy.)
_DANGEROUS_SINKS = frozenset(
    {
        "sql_execute",
        "subprocess_shell",
        "eval",
        "exec",
        "unsafe_deserialization",
        "ssti",
        "ssrf",
        "nosql_injection",
        "dynamic_open",
    }
)


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
            and _method_ok(method, cand.route_method)
        ):
            return cand
    return None


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

        chain = _route_taint(server_scan, link.server_route_path, link.method)
        bola = _route_bola(server_scan, link.server_route_path, link.method)
        if chain is None and bola is None:
            continue

        if chain is not None:
            basis, detail = "taint", chain.sink_kind
            server_file, server_line = chain.sink_file, chain.sink_line
            severity = "high"
        else:
            basis, detail = "bola", f"object access on `{bola.id_param}`"
            server_file, server_line = bola.route_file, bola.route_line
            severity = "high"

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


__all__ = ["CrossBoundaryFlow", "find_cross_boundary_flows"]
