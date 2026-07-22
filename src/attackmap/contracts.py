"""Cross-repo contract linking — cross-repo phase 2 (#146b).

Given a fleet of independently-scanned repos (#146a), link one repo's **outbound
HTTP calls** to another repo's **routes** — the client↔server seam. This is the
one linking dimension that reuses signals both sides already produce
(`ExternalCall.target`/`.method` and `Route.path`/`.method`); the richer
dimensions (RPC callers, shared schemas, queues, DB tables, token iss/aud) are
new extraction deferred to later work.

Matching is by **normalized path template + method**, cross-repo only:

- The call's URL path and the route's path are each normalized to a segment
  tuple with concrete ids and path params collapsed to ``*`` (so
  ``/users/123`` ↔ ``/users/{id}`` ↔ ``/users/:id`` align).
- A link requires the normalized paths to be **equal** and the methods
  compatible (equal, or either side unknown/``ANY``).
- Precision guards: the path must carry at least one **static** segment (a bare
  ``/{id}`` won't link), infra/static routes are excluded, and client and
  server must be **different** repos.

Pure and deterministic — takes ``(repo_id, ScanResult)`` primitives so it stays
unit-testable without a real scan and imports nothing from the CLI/fleet layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import ExternalCall, Route, ScanResult
from .srcpaths import is_infra_route, is_test_file, is_vendored_file

# A path segment that is a concrete instance id rather than a static resource
# name: an explicit path param (`{id}`, `:id`, `<id>`), an all-digits segment,
# a uuid, or a long hex blob. Collapsed to `*` so caller and server templates
# align regardless of how each side writes the variable part.
_PARAM_SEG = re.compile(r"^([{:<].*|.*[}>]|\d+|[0-9a-fA-F-]{16,}|[0-9a-fA-F]{8,})$")
_PLACEHOLDER = "*"


@dataclass(frozen=True)
class ContractLink:
    """A matched client→server seam across two repos."""

    client_repo: str
    server_repo: str
    method: str  # the route's method (the served contract)
    path_template: str  # normalized template, e.g. "users/*"
    client_target: str  # the raw outbound URL as written in the caller
    client_file: str
    client_line: int | None
    server_route_path: str  # the route path as declared on the server
    server_file: str
    server_line: int | None


def _normalize_path(path: str, *, client: bool = False) -> tuple[str, ...] | None:
    """Normalize a URL/route path to a segment tuple with instance ids collapsed
    to ``*``. Returns ``None`` when there is nothing linkable (no path, or only a
    root / all-variable path with no static segment to anchor on).

    ``client=True`` handles the concatenation idiom: an outbound URL built as
    ``base + "/api/orders/" + oid`` is captured only up to the trailing slash, so
    a client path ending in ``/`` is treated as having a dynamic final segment
    (``api/orders/`` → ``("api","orders","*")``) — which then aligns with the
    server template ``/api/orders/{id}`` while still separating from the bare
    collection route ``/api/orders``."""
    if not path:
        return None
    # A full URL (client side) — take just the path component.
    if "://" in path:
        path = urlsplit(path).path
    else:
        path = path.split("?", 1)[0].split("#", 1)[0]
    trailing_slash = path.endswith("/") and path.strip() not in {"", "/"}
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None
    norm = [_PLACEHOLDER if _PARAM_SEG.match(s) else s.lower() for s in segments]
    if client and trailing_slash:
        norm.append(_PLACEHOLDER)  # the concatenated dynamic segment
    # Require at least one static segment — a bare `/{id}` or `/*/*` is too
    # generic to link on without producing spurious cross-repo edges.
    if all(s == _PLACEHOLDER for s in norm):
        return None
    return tuple(norm)


def _method_compatible(call_method: str | None, route_method: str) -> bool:
    """Methods match when they're equal, or either side is unknown/ANY."""
    rm = (route_method or "ANY").upper()
    if call_method is None or rm in {"", "ANY"}:
        return True
    return call_method.upper() == rm


def _excluded_source(rel_file: str) -> bool:
    """Test/spec/fixture and vendored/generated files are not production
    architecture — a cross-repo link anchored on one is noise. Honors the same
    `ATTACKMAP_INCLUDE_TESTS`/`_VENDORED` opt-ins as the rest of the scanner."""
    return is_test_file(rel_file) or is_vendored_file(rel_file)


def _linkable_calls(scan: ScanResult) -> list[tuple[ExternalCall, tuple[str, ...]]]:
    out: list[tuple[ExternalCall, tuple[str, ...]]] = []
    for call in scan.external_calls:
        if _excluded_source(call.file):
            continue
        norm = _normalize_path(call.target, client=True)
        if norm is None:
            continue
        if is_infra_route("/" + "/".join(norm)):
            continue
        out.append((call, norm))
    return out


def _linkable_routes(scan: ScanResult) -> list[tuple[Route, tuple[str, ...]]]:
    out: list[tuple[Route, tuple[str, ...]]] = []
    for route in scan.routes:
        if _excluded_source(route.file):
            continue
        if is_infra_route(route.path):
            continue
        norm = _normalize_path(route.path)
        if norm is None:
            continue
        out.append((route, norm))
    return out


def link_contracts(repo_scans: list[tuple[str, ScanResult]]) -> list[ContractLink]:
    """Return the client→server contract links across a fleet of repos.

    For every ordered pair of *distinct* repos (A as client, B as server), match
    A's linkable outbound calls to B's linkable routes by normalized path +
    method. Deterministic; deduped on the full link identity.
    """
    calls_by_repo = {rid: _linkable_calls(scan) for rid, scan in repo_scans}
    routes_by_repo = {rid: _linkable_routes(scan) for rid, scan in repo_scans}

    links: list[ContractLink] = []
    seen: set[tuple] = set()
    for client_id, _client_scan in repo_scans:
        for call, call_norm in calls_by_repo[client_id]:
            for server_id, _server_scan in repo_scans:
                if server_id == client_id:
                    continue
                for route, route_norm in routes_by_repo[server_id]:
                    if call_norm != route_norm:
                        continue
                    if not _method_compatible(call.method, route.method):
                        continue
                    key = (
                        client_id,
                        server_id,
                        call.file,
                        call.line,
                        route.file,
                        route.method,
                        route.path,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    links.append(
                        ContractLink(
                            client_repo=client_id,
                            server_repo=server_id,
                            method=(route.method or "ANY").upper(),
                            path_template="/".join(call_norm),
                            client_target=call.target,
                            client_file=call.file,
                            client_line=call.line,
                            server_route_path=route.path,
                            server_file=route.file,
                            server_line=route.line,
                        )
                    )
    links.sort(
        key=lambda link: (link.client_repo, link.server_repo, link.path_template, link.method)
    )
    return links


__all__ = ["ContractLink", "link_contracts"]
