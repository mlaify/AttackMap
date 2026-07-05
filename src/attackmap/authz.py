"""Broken object-level authorization (BOLA / IDOR) detection (#69).

OWASP API Security #1. This is the detection AttackMap can do that a
generic linter doesn't emphasize: it composes signals that already exist
in a ``ScanResult`` — routes, per-route auth attribution, datastore
hints, and taint reachability — into a single authorization finding.

## Heuristic

A route is a BOLA/IDOR candidate when ALL of:

1. It takes a **resource identifier** in the path (``/users/{id}``,
   ``/orders/:orderId``, ``/docs/<int:doc_id>``), and
2. It reaches a **datastore** — a DB hint in the same file/module, or a
   taint chain from this route to a ``sql_execute`` sink, and
3. There is **no ownership/authorization check** visible near the
   handler — no ``current_user`` / ``request.user`` / ``owner`` /
   ``authorize`` / policy / guard / ``WHERE user_id``-style scoping in
   the route's file.

Condition 3 is the main false-positive reducer: a well-scoped handler
that filters by the caller's identity is not flagged. Import-edge and
name heuristics are imprecise, so findings are evidence, not proof.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import BolaCandidate, Route, ScanResult

# Path parameter forms across frameworks:
#   {id} {user_id} {int:id}        Flask / FastAPI / Starlette
#   :id :orderId                   Express / Koa / Rails
#   <id> <int:doc_id>              Flask converters
_PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}|:([A-Za-z_]\w*)|<(?:[^:<>]+:)?([^<>]+)>")

# Which extracted params look like a resource identifier an attacker
# would enumerate. Matches `id`, `user_id`, `orderId`, `uuid`, `slug`,
# `*_key`, `guid`, but not generic words like `format` or `lang`.
_ID_PARAM_RE = re.compile(
    r"(?:^|_)id$|^id$|_id$|(?:^|[a-z])Id$|uuid|guid|slug|(?:^|_)key$|hash$|token$|ref$",
    re.IGNORECASE,
)

# Ownership / authorization markers. If ANY appear in the route's file we
# assume authorization is enforced and suppress the finding. Deliberately
# broad — recall on the *suppression* side keeps false positives down.
_OWNERSHIP_MARKERS = re.compile(
    r"""
    current_user | currentUser | \brequest\.user\b | \breq\.user\b | \bctx\.user\b
    | \bowner\b | owner_id | ownerId | user_id\s*(?:==|===|=|:) | userId
    | account_id | tenant_id | org_id | \bself\.user\b
    | authorize | authoriz | \.can\s*\( | cannot | \bpolicy\b | \bpolicies\b
    | \bguard\b | can_access | canAccess | has_access | hasAccess
    | check_access | verify_owner | assert_owner | ensure_owner
    | require[s]?_permission | permission_required | requiresAuth | requireAuth
    | login_required | @authenticated | ensureAuthenticated | is_authorized
    | filter_by\s*\(\s*user | \.where\([^)]*user | WHERE\s+\w*user
    | scope_to | scoped_to | for_user | belongs_to
    """,
    re.IGNORECASE | re.VERBOSE,
)

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_MAX_FILE_BYTES = 1_000_000  # skip absurdly large files


def analyze_authz(scan: ScanResult, root: str | Path | None = None) -> list[BolaCandidate]:
    """Return BOLA/IDOR candidates for routes in ``scan``.

    Only genuine candidates are returned: routes with an ID param that
    reach a datastore AND lack an ownership check. Routes that HAVE an
    ownership check, or don't reach a datastore, are dropped.
    """
    root_path = Path(root or scan.root).resolve()

    # DB reachability sources.
    db_files = {_norm(db.file) for db in scan.databases}
    db_modules = {_module_key(db.file) for db in scan.databases}
    taint_sql_routes = {
        (c.route_method, c.route_path)
        for c in scan.taint_chains
        if c.sink_kind == "sql_execute"
    }

    # Cache file-content ownership-marker checks per file.
    ownership_cache: dict[str, bool] = {}

    seen: set[tuple[str, str, str, str]] = set()
    candidates: list[BolaCandidate] = []

    for route in scan.routes:
        id_param = _resource_id_param(route.path)
        if id_param is None:
            continue

        reaches_db, db_evidence = _db_reachability(
            route, db_files, db_modules, taint_sql_routes
        )
        if not reaches_db:
            continue

        has_check = _file_has_ownership_marker(route.file, root_path, ownership_cache)

        key = (route.method, route.path, route.file, id_param)
        if key in seen:
            continue
        seen.add(key)

        if has_check:
            # Authorization is (probably) enforced — not a candidate.
            continue

        candidates.append(
            BolaCandidate(
                route_path=route.path,
                route_method=route.method,
                route_file=route.file,
                route_line=route.line,
                id_param=id_param,
                reaches_db=True,
                db_evidence=db_evidence,
                has_ownership_check=False,
                source_analyzer="authz",
            )
        )

    candidates.sort(
        key=lambda c: (c.route_method not in _WRITE_METHODS, c.route_file, c.route_path)
    )
    return candidates


# --- Internals -------------------------------------------------------------


def _resource_id_param(path: str) -> str | None:
    """Return the first resource-id-shaped path parameter, or None."""
    for match in _PATH_PARAM_RE.finditer(path):
        raw = next((g for g in match.groups() if g), None)
        if not raw:
            continue
        # Flask converter form `int:id` → take the name after the colon.
        name = raw.split(":")[-1].strip()
        if _ID_PARAM_RE.search(name):
            return name
    return None


def _db_reachability(
    route: Route,
    db_files: set[str],
    db_modules: set[str],
    taint_sql_routes: set[tuple[str, str]],
) -> tuple[bool, str]:
    route_file = _norm(route.file)
    if route_file in db_files:
        return True, "datastore hint in the route's file"
    if _module_key(route.file) in db_modules:
        return True, "datastore hint in the route's module"
    if (route.method, route.path) in taint_sql_routes:
        return True, "taint chain from this route reaches a SQL execute sink"
    return False, ""


def _file_has_ownership_marker(
    rel_file: str, root: Path, cache: dict[str, bool]
) -> bool:
    if rel_file in cache:
        return cache[rel_file]
    path = root / rel_file
    result = False
    try:
        if path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result = _OWNERSHIP_MARKERS.search(content) is not None
    except (OSError, ValueError):
        result = False
    cache[rel_file] = result
    return result


def _norm(rel: str) -> str:
    return rel.replace("\\", "/")


def _module_key(rel: str) -> str:
    """Directory of the file — a coarse 'same module' bucket."""
    norm = _norm(rel)
    return norm.rsplit("/", 1)[0] if "/" in norm else ""


__all__ = ["analyze_authz"]
