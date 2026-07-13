"""Fuse routes + middleware/guard chains + auth_hints into precise findings (#140).

`scan.auth_hints` are raw signals — a large monorepo emits hundreds. They're
useful evidence, but reviewers want conclusions. This pass resolves, *per
route*, whether an authentication/authorization control guards it, and emits a
single precise finding for the state-changing routes that have none — each
carrying the resolved middleware/guard chain as evidence.

Why not reuse `AttackSurface.auth_signals`? That attribution is file-windowed
(±40 lines), so in a compact file every route inherits a neighbor's auth code.
This module resolves the control on the route's *own* registration chain:

- **Express / Koa / Fastify (JS/TS)** — an auth middleware in the route's
  argument list (`app.post('/x', requireAuth, handler)`) or a global
  `app.use(requireAuth)` / `router.use(...)`.
- **FastAPI / Flask (Python)** — an auth decorator (`@login_required`,
  `@jwt_required`, …), a `dependencies=[Depends(...)]` on the route decorator,
  `Depends(<auth>)` / `Security(...)` in the handler signature, or a
  router-level dependency.
- **Spring (Java)** — `@PreAuthorize` / `@PostAuthorize` / `@Secured` /
  `@RolesAllowed` on the method or controller, or a global security config that
  requires authentication for every request.

Scope is deliberately the *general* case — public, state-changing
(`POST/PUT/PATCH/DELETE`) `public_api` routes — because the sensitive
categories (webhook, admin, upload, auth) already have their own dedicated
findings. `auth_hints` emission is untouched; this only consumes them.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import AttackSurface, AttackTechnique, Finding, Route, ScanResult

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_PY_SUFFIXES = {".py"}
_JAVA_SUFFIXES = {".java", ".kt"}

# Identifiers whose presence in a route's chain means it is guarded. Broad
# enough to catch common conventions, specific enough not to match ordinary
# handler code.
_JS_AUTH_TOKEN = re.compile(
    r"\b(?:require(?:Auth|Login|User|Token|Admin)|requiresAuth|isAuthenticated|"
    r"ensureAuth\w*|ensureLoggedIn|ensureAuthenticated|authenticat\w*|authGuard|"
    r"authMiddleware|authenticateJWT|checkAuth|checkJwt|verify(?:Token|Jwt|Auth)|"
    r"jwtMiddleware|passport|protect(?:ed)?Route|withAuth|guard)\b",
    re.IGNORECASE,
)
_PY_AUTH_DECORATOR = re.compile(
    r"@(?:\w+\.)*(?:login_required|jwt_required|token_required|auth_required|"
    r"requires_auth|require_auth|authenticated|permission_required|"
    r"require_(?:oauth|api_key|token)|protected)\b",
    re.IGNORECASE,
)
_PY_DEPENDS_AUTH = re.compile(
    r"(?:Security|Depends)\(\s*(?:[\w.]*)?(?:oauth2_scheme|get_current_user|"
    r"current_user|current_active_user|verify_token|require_\w+|auth\w*|"
    r"authenticate\w*|HTTPBearer|HTTPBasic|JWTBearer|get_user|require_user)",
    re.IGNORECASE,
)
_PY_SECURITY_CALL = re.compile(r"\bSecurity\s*\(")  # fastapi.Security is always auth
_JAVA_AUTH_ANNOTATION = re.compile(
    r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|RoleAllowed|"
    r"Authenticated|HasRole|HasAuthority)\b"
)
_JAVA_GLOBAL_AUTH = re.compile(
    r"\.(?:anyRequest|anyExchange)\s*\(\s*\)\s*\.(?:authenticated|hasRole|hasAuthority|hasAnyRole)"
    r"|\.authorize(?:HttpRequests|Requests|Exchange)\b",
)


def synthesize_unauthenticated_routes(
    scan: ScanResult, surfaces: list[AttackSurface]
) -> list[Finding]:
    """Return at most one finding aggregating unauthenticated state-changing
    public routes, with the resolved control chain per route as evidence."""
    root = Path(scan.root)
    surface_by_key: dict[tuple[str, str, str], AttackSurface] = {}
    for s in surfaces:
        surface_by_key.setdefault((s.method, s.route, s.file), s)

    content_cache: dict[str, str | None] = {}
    # Only pay the Spring-config scan when there are Java routes to attribute —
    # otherwise this is a no-op that would needlessly walk the whole tree.
    has_java_routes = any(
        Path(r.file).suffix.lower() in _JAVA_SUFFIXES for r in scan.routes
    )
    java_global_auth = (
        _repo_has_java_global_auth(scan, root, content_cache) if has_java_routes else False
    )

    flagged: list[tuple[Route, str]] = []
    for route in scan.routes:
        if route.method.upper() not in _MUTATING:
            continue
        surface = surface_by_key.get((route.method, route.path, route.file))
        if surface is None:
            continue
        # The sensitive categories already have dedicated findings; this pass
        # closes the general "ordinary mutating endpoint" gap only.
        if surface.category != "public_api" or surface.exposure != "public":
            continue
        content = _read(root, route.file, content_cache)
        if content is None:
            continue
        control = _resolve_control(route, content, java_global_auth)
        if control is not None:
            continue  # guarded — not a finding
        flagged.append((route, _chain_evidence(route, content)))

    if not flagged:
        return []

    evidence = [chain for _, chain in flagged[:10]]
    if len(flagged) > 10:
        evidence.append(f"+{len(flagged) - 10} more state-changing route(s) with no resolved auth control")
    return [
        Finding(
            title="State-changing routes are reachable without an authentication control",
            severity="high",
            evidence=evidence,
            mitigation=(
                "Require authentication (and server-side authorization) on every "
                "state-changing endpoint — attach an auth middleware/guard to the "
                "route or its router, a dependency/decorator on the handler, or a "
                "global policy that defaults to deny. Confirm the control actually "
                "runs before the handler mutates state."
            ),
            confidence="medium",
            tags=["exposed-endpoint", "auth-missing", "state-changing"],
            attack_techniques=[
                AttackTechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                    url="https://attack.mitre.org/techniques/T1190/",
                )
            ],
        )
    ]


def _read(root: Path, rel: str, cache: dict[str, str | None]) -> str | None:
    if rel not in cache:
        try:
            cache[rel] = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            cache[rel] = None
    return cache[rel]


def _resolve_control(route: Route, content: str, java_global_auth: bool) -> str | None:
    """Return a short description of the control guarding `route`, or None."""
    suffix = Path(route.file).suffix.lower()
    lines = content.splitlines()
    if suffix in _JS_SUFFIXES:
        return _resolve_js(route, content, lines)
    if suffix in _PY_SUFFIXES:
        return _resolve_py(route, lines)
    if suffix in _JAVA_SUFFIXES:
        return _resolve_java(route, lines, java_global_auth)
    return None


def _line_index(route: Route) -> int | None:
    return (route.line - 1) if route.line else None


def _resolve_js(route: Route, content: str, lines: list[str]) -> str | None:
    # Global middleware: app.use(requireAuth) / router.use(passport...).
    for m in re.finditer(r"\b(?:app|router|server)\s*\.\s*use\s*\(([^)]*)\)", content):
        if _JS_AUTH_TOKEN.search(m.group(1)):
            return f"global middleware: {m.group(0).strip()[:80]}"

    idx = _line_index(route)
    if idx is None:
        return None
    # The route registration may span a few lines; take up to the start of the
    # handler body so we inspect the middleware list, not the handler code.
    region = "\n".join(lines[idx : idx + 4])
    handler_start = re.search(r"=>|function\b|\(\s*req\b|\(\s*request\b", region)
    mw_region = region[: handler_start.start()] if handler_start else region
    # Drop the path string literal so a path like '/authenticate' can't match.
    mw_region = re.sub(r"""(['"`])(?:\\.|(?!\1).)*\1""", "", mw_region, count=1)
    if _JS_AUTH_TOKEN.search(mw_region):
        return f"route middleware on {route.path}"
    return None


def _resolve_py(route: Route, lines: list[str]) -> str | None:
    idx = _line_index(route)
    if idx is None:
        return None
    # Decorators can sit above or below the route decorator; scan a small
    # window above, then the handler signature below.
    start = max(0, idx - 4)
    # Find the handler `def`/`async def` at or after the route decorator, then
    # read through the end of its signature (the line with the closing `):`).
    def_line = None
    for i in range(idx, min(len(lines), idx + 6)):
        if re.match(r"\s*(?:async\s+)?def\s+\w+\s*\(", lines[i]):
            def_line = i
            break
    sig_end = def_line if def_line is not None else idx
    if def_line is not None:
        depth = 0
        for i in range(def_line, min(len(lines), def_line + 30)):
            depth += lines[i].count("(") - lines[i].count(")")
            sig_end = i
            if depth <= 0 and "(" in "".join(lines[def_line : i + 1]):
                break
    window = "\n".join(lines[start : sig_end + 1])
    if _PY_AUTH_DECORATOR.search(window):
        return f"auth decorator on {route.path}"
    if _PY_DEPENDS_AUTH.search(window) or _PY_SECURITY_CALL.search(window):
        return f"auth dependency on {route.path} handler"
    # Router-level dependency (applies to every route on the router).
    return _py_router_dependency(lines)


def _py_router_dependency(lines: list[str]) -> str | None:
    text = "\n".join(lines)
    for m in re.finditer(r"(?:APIRouter|include_router)\s*\(([^)]*)\)", text, re.DOTALL):
        if "dependencies" in m.group(1) and _PY_DEPENDS_AUTH.search(m.group(1)):
            return "router-level auth dependency"
    return None


def _resolve_java(route: Route, lines: list[str], java_global_auth: bool) -> str | None:
    if java_global_auth:
        return "global Spring Security policy requires authentication"
    idx = _line_index(route)
    if idx is None:
        return None
    # Method-level annotations sit just above the mapping (after any preceding
    # method's closing brace). Only scan up to that boundary so a *different*
    # method's @PreAuthorize doesn't leak onto this route.
    method_start = 0
    for i in range(idx - 1, -1, -1):
        if "}" in lines[i] or re.search(r"\b(?:public|private|protected)\b.*\)", lines[i]):
            method_start = i + 1
            break
    window = "\n".join(lines[method_start : idx + 1])
    if _JAVA_AUTH_ANNOTATION.search(window):
        return f"method security annotation on {route.path}"
    # Class-level annotations: only those directly above the class declaration.
    for i, line in enumerate(lines):
        if re.search(r"\b(?:class|interface)\s+\w+", line):
            class_head = "\n".join(lines[max(0, i - 6) : i])
            if _JAVA_AUTH_ANNOTATION.search(class_head):
                return "class-level security annotation"
            break
    return None


def _repo_has_java_global_auth(
    scan: ScanResult, root: Path, cache: dict[str, str | None]
) -> bool:
    """True when a Spring Security config requires auth for every request —
    then per-route method annotations aren't needed and routes aren't flagged."""
    java_files = {r.file for r in scan.routes if Path(r.file).suffix.lower() in _JAVA_SUFFIXES}
    # Config usually lives elsewhere; check route files plus any *Security*.java.
    candidates = set(java_files)
    for path in root.rglob("*Security*.java"):
        try:
            candidates.add(str(path.relative_to(root)))
        except ValueError:
            continue
    for rel in candidates:
        content = _read(root, rel, cache)
        if content and "anyRequest" in content and _JAVA_GLOBAL_AUTH.search(content):
            # Require an explicit authenticated()/hasRole() to avoid matching a
            # config that permits all.
            if re.search(r"\.(?:authenticated|hasRole|hasAuthority|hasAnyRole|fullyAuthenticated)\s*\(", content):
                return True
    return False


def _chain_evidence(route: Route, content: str) -> str:
    """Describe what the control-chain resolution found (i.e. nothing)."""
    loc = f"{route.file}:{route.line}" if route.line else route.file
    suffix = Path(route.file).suffix.lower()
    if suffix in _JS_SUFFIXES:
        has_any = bool(_JS_AUTH_TOKEN.search(content))
    elif suffix in _PY_SUFFIXES:
        has_any = bool(_PY_AUTH_DECORATOR.search(content) or _PY_DEPENDS_AUTH.search(content))
    elif suffix in _JAVA_SUFFIXES:
        has_any = bool(_JAVA_AUTH_ANNOTATION.search(content))
    else:
        has_any = False
    tail = (
        "auth controls exist in the file but none guard this route"
        if has_any
        else "no authentication/authorization control found on the route's chain"
    )
    return f"{route.method} {route.path} in {loc} — {tail}"
