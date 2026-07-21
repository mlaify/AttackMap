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

# RPC-method scoping (#139). XRPC methods (`/xrpc/<nsid>`) and tRPC procedures
# (`trpc:<name>`) encode an object operation in the route path. An operation is
# an id-bearing object reference when it names an object-access verb and an
# object noun (`getRecord`, `describeRepo`, `updateProfile`) or a by-id form.
_RPC_OBJECT_VERB_RE = re.compile(
    r"^(get|fetch|load|read|update|delete|put|patch|remove|describe|resolve)", re.IGNORECASE
)
_RPC_OBJECT_NOUN_RE = re.compile(
    r"record|blob|profile|repo|post|account|user|doc|order|item|resource|handle"
    r"|did|actor|thread|message|file|node|entity|comment|session|member|invoice",
    re.IGNORECASE,
)
_RPC_BY_ID_RE = re.compile(r"[Bb]y_?[Ii]d\b")

# GraphQL auth is expressed as schema directives. Their presence on an
# id-bearing field means authorization is enforced → suppress (like the
# ownership markers do for HTTP handlers).
_GRAPHQL_AUTH_DIRECTIVE_RE = re.compile(
    r"@(?:auth|authenticated|isAuthenticated|authorized|hasRole|hasScopes?"
    r"|requiresScopes?|requireAuth|requiresAuth|hasPermission|policy|private|acl)\b",
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
        surface = _id_bearing_surface(route)
        if surface is None:
            continue
        surface_kind, id_param = surface

        # RPC methods and GraphQL fields are object-access operations by
        # definition — they read/write a specific object by id — so the "reaches
        # a datastore" condition is satisfied intrinsically. HTTP path/query
        # surfaces still require an observed datastore link (#139).
        if surface_kind == "rpc_method":
            reaches_db, db_evidence = True, "RPC object-access method"
        else:
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
                surface=surface_kind,  # type: ignore[arg-type]
                reaches_db=True,
                db_evidence=db_evidence,
                has_ownership_check=False,
                source_analyzer="authz",
            )
        )

    # GraphQL fields aren't modeled as routes — scan the repo's SDL directly.
    candidates.extend(_graphql_bola_candidates(root_path, seen))

    candidates.sort(
        key=lambda c: (c.route_method not in _WRITE_METHODS, c.route_file, c.route_path)
    )
    return candidates


# --- Internals -------------------------------------------------------------


def _resource_id_param(path: str) -> str | None:
    """Return the first resource-id-shaped path parameter, or None."""
    # Ignore any query string when scanning path-template params.
    template = path.split("?", 1)[0]
    for match in _PATH_PARAM_RE.finditer(template):
        raw = next((g for g in match.groups() if g), None)
        if not raw:
            continue
        # Flask converter form `int:id` → take the name after the colon.
        name = raw.split(":")[-1].strip()
        if _ID_PARAM_RE.search(name):
            return name
    return None


def _id_bearing_surface(route: Route) -> tuple[str, str] | None:
    """Where an object identifier arrives on this route, if any (#139).

    Returns ``(surface_kind, identifier)`` for the first surface found:
    an RPC method (XRPC/tRPC), an id-bearing query parameter, or a path
    template parameter."""
    rpc = _rpc_method_surface(route.path)
    if rpc is not None:
        return ("rpc_method", rpc)
    query = _query_param_surface(route.path)
    if query is not None:
        return ("query_param", query)
    path_param = _resource_id_param(route.path)
    if path_param is not None:
        return ("path_param", path_param)
    return None


def _rpc_method_surface(path: str) -> str | None:
    """An XRPC NSID (`/xrpc/<nsid>`) or tRPC procedure (`trpc:<name>`) whose
    operation is an id-bearing object reference. Returns the method name."""
    if path.startswith("/xrpc/"):
        method = path[len("/xrpc/"):].split("?", 1)[0]
    elif path.startswith("trpc:"):
        method = path[len("trpc:"):].split("?", 1)[0]
    else:
        return None
    op = method.rsplit(".", 1)[-1]  # terminal operation segment
    if _RPC_BY_ID_RE.search(op):
        return method
    if _RPC_OBJECT_VERB_RE.match(op) and _RPC_OBJECT_NOUN_RE.search(op):
        return method
    return None


def _query_param_surface(path: str) -> str | None:
    """An id-shaped query parameter (`?userId=`, `?doc_id=`), if present."""
    if "?" not in path:
        return None
    query = path.split("?", 1)[1]
    for pair in re.split(r"[&;]", query):
        name = pair.split("=", 1)[0].strip()
        if name and _ID_PARAM_RE.search(name):
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


# --- GraphQL SDL scoping (#139) --------------------------------------------

_GRAPHQL_EXTS = {".graphql", ".gql"}
_GRAPHQL_CODE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb"}
_GRAPHQL_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", "vendor"}
_GRAPHQL_MAX_DEPTH = 6
_GRAPHQL_MAX_FILES = 2000

# `type Query { ... }` / `extend type Mutation { ... }` (SDL field blocks don't
# nest braces, so a non-greedy match to the first `}` is sufficient).
_GRAPHQL_ROOT_BLOCK_RE = re.compile(
    r"(?:extend\s+)?type\s+(?P<kind>Query|Mutation)\b[^{]*\{(?P<body>.*?)\}",
    re.DOTALL,
)
# One field definition: `name(args): ReturnType [@directives]`.
_GRAPHQL_FIELD_RE = re.compile(
    r"(?P<name>\w+)\s*(?:\((?P<args>[^)]*)\))?\s*:\s*(?P<rest>[^\n]*)"
)


def _graphql_bola_candidates(root: Path, seen: set) -> list[BolaCandidate]:
    """Scan the repo's GraphQL SDL for id-bearing Query/Mutation fields that
    lack an authorization directive (#139). GraphQL fields aren't routes, so
    they're modeled here as ``graphql_field`` surfaces."""
    candidates: list[BolaCandidate] = []
    for rel, text in _iter_graphql_sdl(root):
        for match in _GRAPHQL_ROOT_BLOCK_RE.finditer(text):
            is_mutation = match.group("kind") == "Mutation"
            for field in _GRAPHQL_FIELD_RE.finditer(match.group("body")):
                name = field.group("name")
                args = field.group("args") or ""
                rest = field.group("rest") or ""
                arg_id = _graphql_id_arg(args)
                if arg_id is None:
                    continue
                # An auth directive on the field means authorization is enforced.
                if _GRAPHQL_AUTH_DIRECTIVE_RE.search(args + " " + rest):
                    continue
                method = "MUTATION" if is_mutation else "QUERY"
                route_path = f"graphql:{name}"
                key = (method, route_path, rel, arg_id)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    BolaCandidate(
                        route_path=route_path,
                        route_method=method,
                        route_file=rel,
                        id_param=arg_id,
                        surface="graphql_field",
                        reaches_db=True,
                        db_evidence=f"GraphQL {method.lower()} field resolves an object by `{arg_id}`",
                        has_ownership_check=False,
                        source_analyzer="authz",
                    )
                )
    return candidates


def _graphql_id_arg(args: str) -> str | None:
    """Return an id-bearing argument name from a GraphQL field's arg list —
    an id-shaped name (`id`, `userId`) or an `ID`-typed argument."""
    for part in args.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        arg_name, _, arg_type = part.partition(":")
        arg_name = arg_name.strip()
        if _ID_PARAM_RE.search(arg_name):
            return arg_name
        if arg_type.strip().lstrip("[").startswith("ID"):
            return arg_name
    return None


def _iter_graphql_sdl(root: Path):
    """Yield ``(rel_path, text)`` for files that may hold GraphQL SDL: `.graphql`
    / `.gql` files, and code files that contain a `type Query`/`type Mutation`."""
    count = 0

    def walk(directory: Path, depth: int):
        nonlocal count
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            if count >= _GRAPHQL_MAX_FILES:
                return
            if entry.name in _GRAPHQL_SKIP_DIRS:
                continue
            if entry.is_dir():
                if depth < _GRAPHQL_MAX_DEPTH:
                    yield from walk(entry, depth + 1)
                continue
            suffix = entry.suffix.lower()
            if suffix not in _GRAPHQL_EXTS and suffix not in _GRAPHQL_CODE_EXTS:
                continue
            try:
                if entry.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = entry.read_text(encoding="utf-8", errors="ignore")
            except (OSError, ValueError):
                continue
            count += 1
            if suffix in _GRAPHQL_CODE_EXTS and "type Query" not in text and "type Mutation" not in text:
                continue
            rel = _norm(str(entry.relative_to(root)))
            yield rel, text

    yield from walk(root, 1)


def _norm(rel: str) -> str:
    return rel.replace("\\", "/")


def _module_key(rel: str) -> str:
    """Directory of the file — a coarse 'same module' bucket."""
    norm = _norm(rel)
    return norm.rsplit("/", 1)[0] if "/" in norm else ""


__all__ = ["analyze_authz"]
