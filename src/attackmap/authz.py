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
3. There is **no object-level authorization check in the handler** — no
   ownership comparison, caller-scoped query, or policy call inside the
   route's own handler span (``handler_span``), nor in a function the handler
   delegates to (one hop: a same-file helper or an imported service function).

Authentication is not authorization (#242): ``@login_required``,
``requireAuth`` or a ``req.user`` reference prove the caller is *logged in*,
not that they may touch *this* object, so they never suppress a candidate.
They raise its confidence instead — an authenticated route that loads an
object by a client-supplied id with no object check is the classic IDOR.
Import-edge and name heuristics are imprecise, so findings are evidence, not
proof.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from pathlib import Path

from .handler_span import span_text
from .models import AttackSurface, BolaCandidate, Route, ScanResult
from .route_auth_fusion import repo_has_java_global_auth, resolve_control
from .safe_fs import contained_file, is_unsafe_link
from .srcpaths import JS_TS_SUFFIXES, is_test_file, is_vendored_file

# Path parameter forms across frameworks:
#   {id} {user_id} {int:id}        Flask / FastAPI / Starlette
#   :id :orderId                   Express / Koa / Rails
#   <id> <int:doc_id>              Flask converters
_PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}|:([A-Za-z_]\w*)|<(?:[^:<>]+:)?([^<>]+)>")

# Which extracted params look like a resource identifier an attacker
# would enumerate. Matches `id`, `user_id`, `orderId`, `uuid`, `slug`,
# `*_key`, `guid`, Django's `pk`, but not generic words like `format` or `lang`.
_ID_PARAM_RE = re.compile(
    r"(?:^|_)id$|^id$|_id$|(?:^|[a-z])Id$|^pk$|uuid|guid|slug|(?:^|_)key$|hash$|token$|ref$",
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

# Query-parameter scoping (#139). In real framework code the id arrives in the
# handler body, not the registered path — so scan the route's file for an
# id-shaped query-parameter *access* (`req.query.userId`, `request.args.get('id')`,
# `orderId: str = Query(...)`, `searchParams.get('docId')`, …).
_QUERY_ACCESS_RES = (
    re.compile(r"\b(?:req|request|ctx|c)\s*\.\s*(?:query|args|GET|query_params)\s*\.\s*(\w+)"),
    re.compile(r"""\b(?:req|request|ctx|c)\s*\.\s*(?:query|args|GET|query_params)\s*\[\s*['"](\w+)['"]"""),
    re.compile(r"""\b(?:req|request|ctx|c)\s*\.\s*(?:query|args|GET|query_params)\s*\.\s*get\s*\(\s*['"](\w+)['"]"""),
    re.compile(r"""\bsearchParams\s*\.\s*get\s*\(\s*['"](\w+)['"]"""),
    re.compile(r"""\b(\w+)\s*:\s*[\w\[\]|. ]+?=\s*Query\s*\("""),  # FastAPI `id: str = Query(...)`
)

# The caller's identity as handler code spells it (not `get_current_user`).
_PRINCIPAL = (
    r"(?<!\w)(?:current_user|currentUser|request\.user|req\.user|g\.user|ctx\.(?:state\.)?user"
    r"|self\.request\.user|auth\.user|principal|session\[['\"]user\w*['\"]\]"
    r"|session\.user\w*|user\.id\b|me\.id\b)"
)

# Authentication / identity markers (#242): evidence the caller is logged in.
# They say nothing about whether this caller may touch *this* object, so they
# never suppress a candidate; they raise its confidence.
AUTHN_MARKERS = re.compile(
    r"""
    login_required | jwt_required | token_required | auth_required | requires?_auth\b
    | requires?Auth\b | requireLogin | requireUser | isAuthenticated | is_authenticated
    | ensureAuth\w* | ensureLoggedIn | @authenticated\b | passport\.authenticate
    | authGuard | AuthGuard | @UseGuards | \bguard\b | verifyToken | verifyJwt | checkJwt
    | get_current_user | get_current_active_user | Depends\(\s*\w*(?:auth|user)\w*
    | current_user | currentUser | \brequest\.user\b | \breq\.user\b
    | \bctx\.(?:state\.)?user\b | \bg\.user\b | \bself\.user\b
    | @PreAuthorize | @Secured | @RolesAllowed | @Authenticated\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Object-level authorization markers (#242): the handler compares the record
# with the caller, scopes the query by the caller, or asks a policy. Evaluated
# within the handler span (plus one delegated hop), never the whole file.
OBJECT_AUTHZ_MARKERS = re.compile(
    rf"""
    # a record field compared with / scoped to the caller
    (?:owner|user|tenant|account|org|organization|created_by|author)(?:_?id|Id)?
        \s*(?:===?|!==?|=|:|__exact\s*=)\s*[^,;\n)]{{0,40}}?{_PRINCIPAL}
    | {_PRINCIPAL}[^\n]{{0,60}}?(?:===?|!==?)\s*[\w.\[\]'"]*(?:owner|user|author|tenant|account)(?:_?id|Id)\b
    # an ownership field compared with anything
    | \b(?:owner|author)(?:_?id|Id)?\s*(?:!==?|===?)
    | \b(?:\w+\.)?user_?[iI]d\s*(?:!==?|===?)
    # SQL scoping column in a WHERE / AND clause
    | (?:WHERE|AND)\s+[\w.]*(?:owner|user|tenant|account|org)_id\s*=
    # a datastore lookup that carries the caller's identity (a call, not the
    # handler's own `def get_x(id, user=Depends(get_current_user))` signature)
    | (?<!def\s)(?<!function\s)\b(?:find|get|fetch|load|query|select|filter|where|lookup)\w*\s*\([^)\n]*{_PRINCIPAL}
    # relation-scoped access through the caller (current_user.orders.find(id))
    | {_PRINCIPAL}\s*\.\s*\w+?(?:_set)?\s*\.\s*(?:find|get|filter|where|objects|query|first|all)\b
    # explicit authorization / policy calls
    | \bauthorize[!\w]*\s*\( | \bauthorize!?\s+@?\w | \$this->authorize\s*\(
    | Gate::(?:allows|authorize|denies|check) | ->can\s*\( | \.can\s*\( | \bcan\?\s*\(
    | \bcannot\?\s*\( | \bpolic(?:y|ies)\s*[.(] | policy_scope | accessible_by | visible_to
    | owned_by | \bscope_to | scoped_to | for_user | belongs_to
    | can_access | canAccess | has_access | hasAccess | check_access | checkAccess
    | verify_?[oO]wner | assert_?[oO]wner | ensure_?[oO]wner | is_?[oO]wner | check_?[oO]wner\w*
    | has_object_permission | check_object_permissions | require[s]?_permission
    | permission_required | \bhas_perm\b | hasPermission
    | @PreAuthorize\([^)]*(?:\#\w|returnObject|principal|authentication|@\w+)
    | @PostAuthorize | @PostFilter | @PreFilter
    | findBy\w*And(?:Owner|User|Tenant|Account)\w*
    # (?<!\w) + possessive: start once per word, never re-scan it (#236)
    | (?<!\w)\w++(?:(?<=ByOwner)|(?<=ByUser)|(?<=ByTenant)|(?<=ByAccount)
        |(?<=ByOwnerId)|(?<=ByUserId)|(?<=ByTenantId)|(?<=ByAccountId))\s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Function-level authorization (#242, BFLA): a role / permission check, as
# opposed to "is logged in". Evaluated within the handler span, the delegated
# hop, and the route's own middleware chain.
ROLE_MARKERS = re.compile(
    r"""
    \bis_?[aA]dmin\b | \bisSuper\w* | \bis_staff\b | \bis_superuser\b
    | \bhas_?[rR]oles?\b | hasAnyRole | hasAuthority | hasAnyAuthority
    | \brequires?_?[rR]oles?\b | \broles?_required\b | \badmin_required\b | \bsuperuser_required\b
    | \brequires?_?[aA]dmin\w* | \badmin_?[oO]nly\b | \bonlyAdmin\b | \bensureAdmin\b
    | \bcheckAdmin\b | \bverifyAdmin\b | \bisAdminMiddleware\b | \bRolesGuard\b | @Roles\s*\(
    | \bIsAdminUser\b | @staff_member_required | \buser_passes_test\b
    | permission_classes\s*=\s*[\[(][^\])]*(?:Admin|Staff|Superuser|Perm|Role)
    | @Secured | @RolesAllowed
    | @PreAuthorize\([^)]*(?:hasRole|hasAuthority|hasAnyRole|hasAnyAuthority|hasPermission)
    | \bpermission_required\b | \bhas_perm\b | \bhasPermission\b | \brequires?_?[pP]ermissions?\b
    | \bcheck_?[pP]ermissions?\b | \bcan\?\s*\( | \.can\s*\( | ->can\s*\( | \bauthorize[!\w]*\s*\(
    | Gate:: | \.roles?\s*(?:!==?|===?|\bin\b|\bnot\s+in\b) | \brole\s*(?:!==?|===?)\s*['"]
    | \broles\s*\.\s*(?:includes|indexOf|contains)\s*\( | ['"]admin['"]\s+(?:not\s+)?in\s+[\w.]*roles
    | ->userIsAllowed\s*\(
    | (?:\$|->)(?:get)?(?:acl|permissions?|authorization|authz|auth)(?:\(\))?\s*->\s*isAllowed\s*\(
    | \bRolePolicy\s*\( | \bPermissionPolicy\s*\(
    | \brestrictTo\s*\( | \bcheck_?[rR]oles?\s*\( | \ballow(?:ed)?_?[rR]oles\s*\(
    | \brequire[ds]?_?[sS]copes?\s*\( | \bPermissionsGuard\b | \bPoliciesGuard\b
    | @Permissions\s*\( | @CheckPolicies\s*\( | @MembershipRoles\s*\( | @Pbac\s*\(
    | \bguard\s*\.\s*check\s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)
# Symfony authorization (#343). A grant counts unless its attribute is one
# every authenticated session (or every visitor) has. Parsed rather than
# matched with a lookahead, so `IsGranted( 'ROLE_USER' )` and
# `IsGranted(attribute: 'IS_AUTHENTICATED_FULLY')` can't slip through.
_SYMFONY_GRANT_RE = re.compile(
    r"\b(?:IsGranted|isGranted|denyAccessUnlessGranted|is_granted)\s*+\(\s*+(?:attribute\s*+:\s*+)?"
)
_SYMFONY_SECURITY_RE = re.compile(r"(?:#\[\s*+|@)(?:[\w\\]{0,200}\\)?Security\s*+\(")
_GRANT_ARG_RE = re.compile(r"""'([^'\n]{0,200})'|"([^"\n]{0,200})"|(?:[\w\\]{1,200}::)?(\w+)""")
_ROLE_CONST_RE = re.compile(r"\bROLE_[A-Z][A-Z0-9_]*")
_SYMFONY_NON_ROLES = frozenset(
    {
        "IS_AUTHENTICATED", "IS_AUTHENTICATED_FULLY", "IS_AUTHENTICATED_REMEMBERED",
        "IS_AUTHENTICATED_ANONYMOUSLY", "IS_ANONYMOUS", "IS_REMEMBERED", "IS_IMPERSONATOR",
        "PUBLIC_ACCESS", "ROLE_USER", "ROLE_ANONYMOUS", "ROLE_PREVIOUS_ADMIN",
    }
)
# Symfony `access_control` rules a plugin declares as a guard
# (`access_control ^/admin: ROLE_ADMIN`); read from Route.guards only.
_ACCESS_CONTROL_GUARD_RE = re.compile(r"\baccess_control\b")
_SYMFONY_SCAN = 400


def _symfony_role_check(text: str) -> bool:
    """A Symfony grant of a role or voter permission other than the ones
    every session has: ``#[IsGranted(...)]``, ``isGranted(...)``,
    ``denyAccessUnlessGranted(...)``, or a ``#[Security(...)]`` expression
    naming such a role."""
    if "ranted" not in text and "Security" not in text and "is_granted" not in text:
        return False
    for match in _SYMFONY_GRANT_RE.finditer(text):
        arg = _GRANT_ARG_RE.match(text, match.end(), match.end() + _SYMFONY_SCAN)
        if arg is None:
            return True  # an expression, array or variable: still an authorization call
        value = next(group for group in arg.groups() if group is not None)
        if value not in _SYMFONY_NON_ROLES:
            return True
    for match in _SYMFONY_SECURITY_RE.finditer(text):
        body = text[match.end() : match.end() + _SYMFONY_SCAN]
        if any(role not in _SYMFONY_NON_ROLES for role in _ROLE_CONST_RE.findall(body)):
            return True
    return False


def has_role_check(text: str) -> bool:
    """A role or permission check in ``text`` (handler code or guards)."""
    return bool(ROLE_MARKERS.search(text)) or _symfony_role_check(text)


# Guard *names* (as plugins put them in Route.guards, #349) that are a role or
# permission check. Matched against the whole name, with any `@` and call
# arguments stripped, so these generic words (`permit`, `acl`, `rbac`) only
# count as a guard, never as a word in handler code (`params.permit(...)`).
# A plugin can also mark any guard explicitly with a `role:` prefix.
_ROLE_GUARD_NAMES = frozenset(
    name.lower()
    for name in (
        "restrictTo", "permit", "checkRole", "checkRoles", "rbac", "acl", "allowRoles", "allowedRoles",
        "authorizeRoles", "guard.check", "requireScopes", "requiredScopes", "requireScope", "requiredScope",
        "PermissionsGuard", "PermissionGuard", "PoliciesGuard", "PolicyGuard", "Permissions", "CheckPolicies",
        "MembershipRoles", "Pbac", "Roles", "RolesGuard", "RoleGuard",
    )
)
_GUARD_NAME_RE = re.compile(r"^\s*@?\s*([\w.$]{1,120})")


def _role_guard_name(guard: str) -> bool:
    if guard.strip().lower().startswith("role:"):
        return True
    match = _GUARD_NAME_RE.match(guard)
    return match is not None and match.group(1).lower() in _ROLE_GUARD_NAMES


def _guards_role_check(route: Route) -> bool:
    """Plugin-declared guards with role semantics, including Symfony
    ``access_control`` rules naming a role other than ROLE_USER & co."""
    if any(_role_guard_name(guard) for guard in route.guards):
        return True
    text = " ".join(route.guards) + " " + (route.guard_evidence or "")
    if has_role_check(text):
        return True
    return any(
        _ACCESS_CONTROL_GUARD_RE.search(guard)
        and any(role not in _SYMFONY_NON_ROLES for role in _ROLE_CONST_RE.findall(guard))
        for guard in route.guards
    )


_JS_USE_RE = re.compile(r"\b(?:app|router|server|\w+Router)\s*\.\s*use\s*\(([^)]*)\)")
_PY_ROUTER_DEPS_RE = re.compile(r"(?:APIRouter|include_router)\s*\(([^)]*)\)", re.DOTALL)
_CLASS_DECL_RE = re.compile(r"\b(?:class|interface)\s+\w+")
# Route declarations that live in configuration rather than code (#343):
# data formats, and PHP files that are a returned config array (Laminas /
# Omeka `routes.config.php`, Mezzio `routes.php`). The handler (a
# controller) is elsewhere, so the route's span there is not its handler.
_CONFIG_ROUTE_SUFFIXES = frozenset({".yaml", ".yml", ".xml", ".json", ".ini", ".neon", ".toml"})
_PHP_OPEN_RE = re.compile(r"<\?php\b")
_PHP_PREAMBLE_RE = re.compile(
    r"\s+|//[^\n]*|#(?!\[)[^\n]*|/\*|declare\s*\([^)]{0,200}\)\s*;|namespace\s+[\w\\]+\s*;|use\s+[^;]{1,500};"
)
_PHP_RETURN_ARRAY_RE = re.compile(r"return\s*(?:\[|array\s*\()", re.IGNORECASE)
# A handler written inline in the config (a closure) is visible after all.
_INLINE_HANDLER_RE = re.compile(r"\bfunction\s*\(|\bfn\s*\(")


# A Symfony YAML/XML route's controller: `controller: App\Controller\X::y`,
# `_controller: ...` under `defaults`, `controller="..."`, or
# `<default key="_controller">...</default>`.
_CONFIG_CONTROLLER_RE = re.compile(
    r"""(?:\b_?controller['"]?\s*+[:=]|\bkey\s*+=\s*+['"]_controller['"]\s*+>)\s*+['"]?\\?"""
    r"""([A-Za-z_][\w\\]{0,300})(?:::(\w+))?"""
)
_PHP_FUNCTION_RE = re.compile(r"\bfunction\s++&?\s*+(\w+)\s*+\(")
_CONTROLLER_ATTR_LINES = 15


class _ConfigControllerResolver:
    """Resolve a config-declared Symfony route to its controller method via
    the repo's composer PSR-4 map, and return the method's text plus the
    attributes on it and on its class (#343). Files are read through
    ``contained_file``; nothing outside the repo is followed."""

    def __init__(self, root: Path, cache: dict[str, str | None]):
        self.root = root
        self.cache = cache
        self._psr4: list[tuple[str, str]] | None = None

    def _autoload(self) -> list[tuple[str, str]]:
        if self._psr4 is None:
            self._psr4 = []
            text = _read_file_content("composer.json", self.root, self.cache)
            try:
                data = json.loads(text) if text else {}
            except ValueError:
                data = {}
            psr4 = data.get("autoload", {}).get("psr-4", {}) if isinstance(data, dict) else {}
            if isinstance(psr4, dict):
                for prefix, dirs in list(psr4.items())[:64]:
                    for directory in [dirs] if isinstance(dirs, str) else (dirs if isinstance(dirs, list) else []):
                        if isinstance(prefix, str) and isinstance(directory, str):
                            self._psr4.append((prefix, directory))
            self._psr4.sort(key=lambda item: -len(item[0]))
        return self._psr4

    def resolve(self, config_file: str, span: str) -> tuple[str, str, str, str] | None:
        """``(controller file, its content, method + attributes text,
        "Class::method")`` or None when the span names no resolvable
        controller (only data-format route files are followed)."""
        if Path(config_file).suffix.lower() not in _CONFIG_ROUTE_SUFFIXES:
            return None
        match = _CONFIG_CONTROLLER_RE.search(span)
        if match is None:
            return None
        cls, method = match.group(1).strip("\\"), match.group(2) or "__invoke"
        rel_file = next(
            (
                directory.rstrip("/") + "/" + cls[len(prefix) :].replace("\\", "/") + ".php"
                for prefix, directory in self._autoload()
                if cls.startswith(prefix)
            ),
            None,
        )
        if rel_file is None:
            return None
        rel_file = posixpath.normpath(rel_file)
        if rel_file.startswith(".."):
            return None
        content = _read_file_content(rel_file, self.root, self.cache)
        if not content:
            return None
        lines = content.splitlines()
        # (0-based line, name) of each function, counting newlines once.
        starts: list[tuple[int, str]] = []
        line_no = pos = 0
        for m in _PHP_FUNCTION_RE.finditer(content):
            line_no += content.count("\n", pos, m.start())
            pos = m.start()
            starts.append((line_no, m.group(1)))
        index = next((i for i, (_, name) in enumerate(starts) if name == method), None)
        if index is None:
            return None
        first = starts[index][0]
        if index + 1 < len(starts):
            # Stop above the next method's own attributes / docblock: they
            # describe it, not this one.
            last = starts[index + 1][0]
            last -= len(_leading_attributes(lines, last))
        else:
            last = len(lines)
        body = _leading_attributes(lines, first) + lines[first : min(last, first + _AUTHZ_SPAN)]
        class_line = next((i for i, line in enumerate(lines[:first]) if _CLASS_DECL_RE.search(line)), None)
        class_attrs = _leading_attributes(lines, class_line) if class_line is not None else []
        return rel_file, content, "\n".join(class_attrs + body), f"{cls}::{method}"


def _leading_attributes(lines: list[str], index: int) -> list[str]:
    """The attribute / docblock lines directly above ``lines[index]``,
    stopping at the previous member (a line ending in ``;``, ``{`` or ``}``)."""
    start = index
    while start > 0 and index - start < _CONTROLLER_ATTR_LINES:
        previous = lines[start - 1].rstrip()
        if previous.endswith((";", "{", "}")):
            break
        start -= 1
    return lines[start:index]


def is_config_route_file(file: str, content: str) -> bool:
    """True when ``file`` declares routes as configuration: a data format,
    or a PHP file whose first statement is ``return [...]`` /
    ``return array(...)`` (after ``namespace`` / ``use`` / ``declare`` and
    comments)."""
    suffix = Path(file).suffix.lower()
    if suffix in _CONFIG_ROUTE_SUFFIXES:
        return True
    if suffix != ".php":
        return False
    opener = _PHP_OPEN_RE.match(content.lstrip("\ufeff"))
    if not opener:
        return False
    text = content.lstrip("\ufeff")
    pos = opener.end()
    # Each step consumes at least one character, so this is linear.
    for _ in range(10_000):
        match = _PHP_PREAMBLE_RE.match(text, pos)
        if not match:
            break
        if match.group() == "/*":
            end = text.find("*/", match.end())
            if end < 0:
                return False
            pos = end + 2
        else:
            pos = match.end()
    return _PHP_RETURN_ARRAY_RE.match(text, pos) is not None


def find_bfla_routes(
    scan: ScanResult, surfaces: list[AttackSurface], root: str | Path | None = None
) -> list[tuple[Route, str]]:
    """Privileged (``admin``) routes that resolve an authentication control
    but no role or permission check (#242, OWASP API5 BFLA), each with its
    evidence line. Routes with no authentication at all are left to the
    unauthenticated-route findings."""
    root_path = Path(root or scan.root).resolve()
    admin_keys = {(s.method, s.route, s.file) for s in surfaces if s.category == "admin"}
    if not admin_keys:
        return []
    content_cache: dict[str, str | None] = {}
    hop = _HopResolver(root_path, content_cache)
    route_lines: dict[str, list[int]] = {}
    for r in scan.routes:
        if r.line is not None:
            route_lines.setdefault(r.file, []).append(r.line)
    java_global_auth: bool | None = None
    lines_cache: dict[str, list[str]] = {}
    chain_role_cache: dict[str, bool] = {}
    config_cache: dict[str, bool] = {}
    controllers = _ConfigControllerResolver(root_path, content_cache)
    out: list[tuple[Route, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for route in scan.routes:
        key = (route.method, route.path, route.file)
        if key not in admin_keys or key in seen:
            continue
        seen.add(key)
        if route.auth == "anonymous":
            continue
        content = _read_file_content(route.file, root_path, content_cache)
        if not content:
            continue
        if (
            java_global_auth is None
            and route.auth != "required"
            and Path(route.file).suffix.lower() in _JAVA_SUFFIXES
        ):
            java_global_auth = repo_has_java_global_auth(scan, root_path, content_cache)
        if route.auth == "required":
            authn = "authentication declared" + (f" by {route.source_analyzer}" if route.source_analyzer else "")
        else:
            authn = resolve_control(route, content, bool(java_global_auth)) or ""
        if not authn:
            continue
        if _guards_role_check(route):
            continue  # the plugin resolved a role check
        if route.file not in lines_cache:
            lines_cache[route.file] = content.splitlines()
            chain_role_cache[route.file] = _chain_role_check(route, content)
        handler = span_text(
            route.line, lines_cache[route.file], route_lines.get(route.file, []), max_span=_AUTHZ_SPAN
        )
        where = f"{route.file}:{route.line}" if route.line else route.file
        if route.file not in config_cache:
            config_cache[route.file] = is_config_route_file(route.file, content)
        if config_cache[route.file] and not _INLINE_HANDLER_RE.search(handler):
            # Declared in config (#343): the span here is configuration, not
            # the handler. Follow a Symfony YAML/XML `controller` reference
            # to the controller method; when there is none to follow
            # (Laminas / Omeka PHP arrays), finding no role check in the
            # config says nothing, so the route isn't flagged.
            resolved = controllers.resolve(route.file, handler)
            if resolved is None:
                continue
            ctrl_file, ctrl_content, ctrl_text, target = resolved
            if has_role_check(ctrl_text) or has_role_check(hop.delegated_text(ctrl_file, ctrl_content, ctrl_text)):
                continue
            out.append(
                (route, f"{route.method} {route.path} in {where} (handler {target}) — {authn}, but no role or permission check")
            )
            continue
        if (
            chain_role_cache[route.file]
            or has_role_check(handler)
            or has_role_check(hop.delegated_text(route.file, content, handler))
        ):
            continue
        out.append(
            (route, f"{route.method} {route.path} in {where} — {authn}, but no role or permission check")
        )
    return out


def _chain_role_check(route: Route, content: str) -> bool:
    """A role check on the route's router/controller rather than the handler:
    a JS ``router.use(requireRole(...))``, a FastAPI router dependency, or a
    Java class-level annotation."""
    suffix = Path(route.file).suffix.lower()
    if suffix in JS_TS_SUFFIXES:
        return any(ROLE_MARKERS.search(m.group(1)) for m in _JS_USE_RE.finditer(content))
    if suffix == ".py":
        return any(
            "dependencies" in m.group(1) and ROLE_MARKERS.search(m.group(1))
            for m in _PY_ROUTER_DEPS_RE.finditer(content)
        )
    if suffix in _JAVA_SUFFIXES:
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if _CLASS_DECL_RE.search(line):
                return bool(ROLE_MARKERS.search("\n".join(lines[max(0, i - 6) : i])))
    return False


# GraphQL resolver files keep the original whole-file marker set (#139):
# fields aren't routes, so there is no handler span to scope to yet.
_GRAPHQL_RESOLVER_AUTH = re.compile(
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

# A handler span long enough to hold a whole handler body; the anomaly
# detector's 40-line default would miss a check deep in a long handler and
# turn it into a false positive.
_AUTHZ_SPAN = 150
# One-hop delegation budget per route (#242).
_MAX_HOPS = 6
_MAX_HOP_LINES = 80
_MAX_IMPORTS = 40

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_MAX_FILE_BYTES = 1_000_000  # skip absurdly large files


def analyze_authz(scan: ScanResult, root: str | Path | None = None) -> list[BolaCandidate]:
    """Return BOLA/IDOR candidates for routes in ``scan``.

    Only genuine candidates are returned: routes with an ID param that
    reach a datastore AND lack an object-level authorization check in their
    handler. Routes that HAVE one, or don't reach a datastore, are dropped.
    Candidates on authenticated routes are ``high`` confidence (#242).
    """
    root_path = Path(root or scan.root).resolve()

    # DB reachability sources.
    db_files = {_norm(db.file) for db in scan.databases}
    db_modules = {_module_key(db.file) for db in scan.databases}
    taint_sql_routes = {
        (c.route_method, c.route_path)
        for c in scan.taint_chains
        # Speculative recall chains (#148a) are unconfirmed leads — they must
        # not manufacture an asserted HIGH BOLA finding that could trip the
        # baseline gate.
        if c.sink_kind == "sql_execute" and not c.speculative
    }

    # Cache per-file content (read at most once per route file), and the
    # file-level query-param scan: it depends only on the file, and redoing it
    # per route made a many-route file quadratic (#218).
    content_cache: dict[str, str | None] = {}
    query_param_cache: dict[str, str | None] = {}
    lines_cache: dict[str, list[str]] = {}
    chain_role_cache: dict[str, bool] = {}
    hop = _HopResolver(root_path, content_cache)

    # Handler spans end at the next route declared in the same file.
    route_lines: dict[str, list[int]] = {}
    for r in scan.routes:
        if r.line is not None:
            route_lines.setdefault(r.file, []).append(r.line)
    java_global_auth: bool | None = None  # resolved lazily: it walks the repo

    seen: set[tuple[str, str, str, str]] = set()
    candidates: list[BolaCandidate] = []

    for route in scan.routes:
        content = _read_file_content(route.file, root_path, content_cache)

        # Path-encoded surfaces (RPC method, path template param) first; then
        # fall back to an id-shaped query-parameter access in the handler body.
        surface = _path_based_surface(route.path)
        if surface is None and content:
            if route.file not in query_param_cache:
                query_param_cache[route.file] = _query_param_in_handler(content)
            qp = query_param_cache[route.file]
            if qp is not None:
                surface = ("query_param", qp)
        if surface is None:
            continue
        surface_kind, id_param = surface

        # RPC methods are object-access operations by definition — they read/
        # write a specific object by id — so the "reaches a datastore" condition
        # is satisfied intrinsically. HTTP path/query surfaces still require an
        # observed datastore link (#139).
        if surface_kind == "rpc_method":
            reaches_db, db_evidence = True, "RPC object-access method"
        else:
            reaches_db, db_evidence = _db_reachability(
                route, db_files, db_modules, taint_sql_routes
            )
        if not reaches_db:
            continue

        key = (route.method, route.path, route.file, id_param)
        if key in seen:
            continue
        seen.add(key)

        handler = ""
        if content:
            if route.file not in lines_cache:
                lines_cache[route.file] = content.splitlines()
            handler = span_text(
                route.line, lines_cache[route.file], route_lines.get(route.file, []), max_span=_AUTHZ_SPAN
            )
        delegated = hop.delegated_text(route.file, content, handler) if handler else ""
        scope = handler + "\n" + delegated
        if OBJECT_AUTHZ_MARKERS.search(scope):
            # Object-level authorization is (probably) enforced — not a candidate.
            continue
        if content and route.file not in chain_role_cache:
            chain_role_cache[route.file] = _chain_role_check(route, content)
        if has_role_check(scope) or chain_role_cache.get(route.file, False):
            # A role-gated route (admin tooling) reaches any object by design.
            continue

        if (
            java_global_auth is None
            and route.auth != "required"
            and Path(route.file).suffix.lower() in _JAVA_SUFFIXES
        ):
            java_global_auth = repo_has_java_global_auth(scan, root_path, content_cache)
        authn = _authn_evidence(route, content, handler, bool(java_global_auth))

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
                authn_evidence=authn,
                confidence="high" if authn else "medium",
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

_JAVA_SUFFIXES = {".java", ".kt"}


def _authn_evidence(route: Route, content: str | None, handler: str, java_global_auth: bool) -> str:
    """How the route is known to be authenticated, or "" when it isn't."""
    if route.auth == "required":
        return "authentication declared" + (f" by {route.source_analyzer}" if route.source_analyzer else "")
    if route.auth == "anonymous":
        return ""
    if content:
        control = resolve_control(route, content, java_global_auth)
        if control:
            return control
    match = AUTHN_MARKERS.search(handler)
    if match:
        return f"authenticated handler (`{match.group(0).strip()}`)"
    return ""


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


def _path_based_surface(path: str) -> tuple[str, str] | None:
    """Object-identifier surfaces encoded in the route path (#139): an RPC
    method (XRPC/tRPC) or a path-template parameter. Query parameters are
    resolved from the handler body separately (they aren't in the path)."""
    rpc = _rpc_method_surface(path)
    if rpc is not None:
        return ("rpc_method", rpc)
    path_param = _resource_id_param(path)
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


def _query_param_in_handler(content: str) -> str | None:
    """An id-shaped query parameter read in the handler file, if any — e.g.
    `req.query.userId`, `request.args.get('doc_id')`, `id: str = Query(...)`."""
    for regex in _QUERY_ACCESS_RES:
        for match in regex.finditer(content):
            name = match.group(1)
            if name and _ID_PARAM_RE.search(name):
                return name
    return None


def _read_file_content(rel_file: str, root: Path, cache: dict[str, str | None]) -> str | None:
    if rel_file in cache:
        return cache[rel_file]
    content: str | None = None
    try:
        path = contained_file(root, rel_file)
        if path is not None and path.stat().st_size <= _MAX_FILE_BYTES:
            content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        content = None
    cache[rel_file] = content
    return content


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


# --- One-hop delegation (#242) ---------------------------------------------

_IDENT_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\b")
# Names never worth resolving as a delegated function.
_HOP_SKIP = frozenset(
    {
        "if", "for", "while", "return", "await", "async", "def", "function", "const", "let",
        "var", "new", "class", "self", "this", "req", "res", "request", "response", "ctx",
        "next", "print", "len", "str", "int", "dict", "list", "json", "app", "router",
        "get", "post", "put", "patch", "delete", "route", "db", "jsonify", "abort",
    }
)
_PY_FROM_IMPORT_RE = re.compile(
    r"^[ \t]*from\s+(?P<mod>\.*[\w.]*)\s+import\s+(?P<names>\([^)]*\)|[^\n#]+)", re.MULTILINE
)
_PY_IMPORT_RE = re.compile(r"^[ \t]*import\s+(?P<mod>[\w.]+)(?:\s+as\s+(?P<alias>\w+))?", re.MULTILINE)
_JS_IMPORT_FROM_RE = re.compile(r"""import\s+(?P<clause>[^;'"]+?)\s+from\s+["'](?P<spec>\.[^"']*)["']""")
_JS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<clause>\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*["'](?P<spec>\.[^"']*)["']\s*\)"""
)
_JS_PROBE_SUFFIXES = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
_TS_FOR_JS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
_CALL_OR_REF_RE = re.compile(r"(?<!\s)\s*[(,)]")  # anchored: linear under search() (#236)
_ARROW_EXPR_RE = re.compile(r"=>\s*[^\s{]")


# A function, method or class definition; whichever group matched names it.
_DEF_RE = re.compile(
    r"^[ \t]*(?:async\s+)?def\s+(?P<a>\w+)\s*\("
    r"|^[ \t]*class\s+(?P<b>[A-Za-z_$][\w$]*)"
    r"|^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<c>[A-Za-z_$][\w$]*)\s*\("
    r"|^[ \t]*(?:export\s+)?(?:const|let|var)\s+(?P<d>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)"
    r"|^[ \t]*(?:exports|module\.exports)\.(?P<e>[A-Za-z_$][\w$]*)\s*="
    r"|^[ \t]*(?:(?:public|private|protected|static|async)\s+)*(?P<f>[A-Za-z_$][\w$]*)\s*\([^)\n]*\)\s*(?::\s*[^{\n]+)?\{"
    r"|^[ \t]*(?:public|private|protected)\s+[\w<>\[\], ?]+\s+(?P<g>\w+)\s*\(",
    re.MULTILINE,
)
_NOT_DEFS = frozenset({"if", "for", "while", "switch", "catch", "function", "return", "with"})


def _definition_index(text: str) -> dict[str, int]:
    """Defined name → 0-based line of its first definition in ``text``."""
    index: dict[str, int] = {}
    for m in _DEF_RE.finditer(text):
        name = next(g for g in m.groups() if g)
        if name not in _NOT_DEFS and name not in index:
            index[name] = text.count("\n", 0, m.start())
    return index


_INLINE_STRING_RE = re.compile(r"""'(?:\\.|[^'\\\n])*+'|"(?:\\.|[^"\\\n])*+"|`(?:\\.|[^`\\\n])*+`""")


# A body that opens and closes on one line, after a parameter list or arrow:
# `f(x): boolean { return x; }`, `function h($r) { return $next($r); }`.
_ONE_LINE_BODY_RE = re.compile(r"(?:\)|=>)\s*+(?::\s*+[^{=;]{1,80}?)?\s*+\{[^{}]*+\}")


def _block_from(lines: list[str], start: int) -> str:
    """The definition starting at ``lines[start]``: an indented Python block,
    or a brace-balanced block, capped at ``_MAX_HOP_LINES``."""
    head = lines[start]
    end = min(len(lines), start + _MAX_HOP_LINES)
    if head.rstrip().endswith(":") or re.match(r"\s*(?:async\s+)?def\b|\s*class\b", head):
        indent = len(head) - len(head.lstrip())
        out = [head]
        for line in lines[start + 1 : end]:
            if line.strip() and len(line) - len(line.lstrip()) <= indent and not line.lstrip().startswith(")"):
                break
            out.append(line)
        return "\n".join(out)
    if "{" not in head and (_ARROW_EXPR_RE.search(head) or head.rstrip().endswith(";")):
        return head  # `const f = (id) => Doc.findById(id);` — a one-line definition
    depth = 0
    parens = 0
    opened = False
    out = []
    for i, line in enumerate(lines[start:end]):
        out.append(line)
        # Braces inside string and template literals don't open or close the
        # body (`\`${s.slice(0, -1)},"k":${v}}\`` closed it early) (#366).
        code = _INLINE_STRING_RE.sub('""', line)
        depth += code.count("{") - code.count("}")
        parens += code.count("(") - code.count(")")
        # A body is open once the braces stay open past a line: braces that
        # open and close on one line (`({ secret }: { secret: string }) =>`,
        # a curried middleware factory's parameters) aren't the body (#366).
        if not opened and depth <= 0 and _ONE_LINE_BODY_RE.search(code):
            # `canActivate() { return true; }`: the body opened and closed on
            # this line; don't run on into the next member.
            break
        opened = opened or depth > 0
        if opened and depth <= 0:
            break
        if not opened and i >= 3 and parens <= 0:
            # Never found a body (a parameter list still open doesn't count:
            # `const f = (\n a,\n b,\n c,\n) => {`); don't swallow what follows.
            return head
    return "\n".join(out)


class _HopResolver:
    """Resolve the functions a handler delegates to — a same-file helper or a
    function in a module the route file imports — and return their bodies.

    Bounded: one hop, ``_MAX_HOPS`` definitions per handler, ``_MAX_HOP_LINES``
    lines each, and only intra-repo modules reached through ``contained_file``.
    """

    def __init__(self, root: Path, cache: dict[str, str | None]):
        self.root = root
        self.cache = cache
        self._imports: dict[str, dict[str, str]] = {}
        self._defs: dict[str, tuple[list[str], dict[str, int]]] = {}

    def delegated_text(
        self,
        rel_file: str,
        content: str | None,
        handler: str,
        located: list[tuple[str, int, str]] | None = None,
    ) -> str:
        """The bodies ``handler`` delegates to, joined. ``located``, when given,
        also receives ``(file, 1-based start line, body)`` for each one."""
        if not content:
            return ""
        imports = self._import_map(rel_file, content)
        bodies: list[str] = []
        tried: set[tuple[str, str]] = set()
        for match in _IDENT_RE.finditer(handler):
            if len(bodies) >= _MAX_HOPS:
                break
            name = match.group(1)
            if name in _HOP_SKIP:
                continue
            # `svc.get_invoice(…)` → look `get_invoice` up in whatever `svc` names.
            after = handler[match.end() : match.end() + 64]
            member = re.match(r"\s*\.\s*([A-Za-z_$][\w$]*)", after)
            if name in imports and member is not None:
                target, func = imports[name], member.group(1)
            elif member is None and _CALL_OR_REF_RE.match(after):
                # A call, or a handler passed by reference (`router.get(p, getDoc)`);
                # a bare mention (`Order.query…`, a variable) is not delegation.
                target, func = imports.get(name, rel_file), name
            else:
                continue
            if (target, func) in tried:
                continue
            tried.add((target, func))
            body = self._definition(target, func)
            if body:
                bodies.append(body)
                if located is not None:
                    located.append((target, self._defs[target][1][func] + 1, body))
        return "\n".join(bodies)

    def _definition(self, rel_file: str, name: str) -> str:
        if rel_file not in self._defs:
            text = _read_file_content(rel_file, self.root, self.cache) or ""
            self._defs[rel_file] = (text.splitlines(), _definition_index(text))
        lines, index = self._defs[rel_file]
        start = index.get(name)
        return _block_from(lines, start) if start is not None else ""

    def _import_map(self, rel_file: str, content: str) -> dict[str, str]:
        """Binding name → intra-repo module (rel path) for the route file."""
        if rel_file in self._imports:
            return self._imports[rel_file]
        out: dict[str, str] = {}
        base = Path(_norm(rel_file)).parent
        if Path(rel_file).suffix == ".py":
            for m in _PY_FROM_IMPORT_RE.finditer(content):
                mod = m.group("mod")
                names = m.group("names").strip().strip("()").replace("\n", " ")
                for part in names.split(","):
                    bits = part.strip().split(" as ")
                    real, alias = bits[0].strip(), bits[-1].strip()
                    if not alias.isidentifier():
                        continue
                    # `from pkg import module` binds a module; `from mod import func` a symbol.
                    target = self._py_module(base, f"{mod}.{real}" if not mod.endswith(".") else f"{mod}{real}")
                    target = target or self._py_module(base, mod)
                    if target:
                        out.setdefault(alias, target)
                    if len(out) >= _MAX_IMPORTS:
                        break
            for m in _PY_IMPORT_RE.finditer(content):
                target = self._py_module(base, m.group("mod"))
                if target:
                    out.setdefault(m.group("alias") or m.group("mod").split(".")[0], target)
        else:
            for regex in (_JS_IMPORT_FROM_RE, _JS_REQUIRE_RE):
                for m in regex.finditer(content):
                    target = self._js_module(base, m.group("spec"))
                    if target is None:
                        continue
                    clause = m.group("clause")
                    for name in re.findall(r"[A-Za-z_$][\w$]*", clause.replace(" as ", " ")):
                        if name not in {"as", "type"}:
                            out.setdefault(name, target)
                    if len(out) >= _MAX_IMPORTS:
                        break
        self._imports[rel_file] = out
        return out

    def _py_module(self, base: Path, module: str) -> str | None:
        dots = len(module) - len(module.lstrip("."))
        parts = [p for p in module.lstrip(".").split(".") if p]
        if not parts:
            return None
        if dots:
            anchors = [base.joinpath(*([".."] * (dots - 1)))]
        else:
            anchors = [Path(""), base]
        for anchor in anchors:
            for cand in (anchor.joinpath(*parts).with_suffix(".py"), anchor.joinpath(*parts, "__init__.py")):
                rel = self._existing(cand)
                if rel:
                    return rel
        return None

    def _js_module(self, base: Path, spec: str) -> str | None:
        target = base / spec
        cands = [target] if target.suffix in _JS_PROBE_SUFFIXES else []
        # TypeScript ESM imports name the emitted file: `from './webhook.js'`
        # is `webhook.ts` in the source tree (#366).
        cands += [target.with_suffix(sfx) for sfx in _TS_FOR_JS.get(target.suffix, ())]
        cands += [target.parent / (target.name + sfx) for sfx in _JS_PROBE_SUFFIXES]
        cands += [target / f"index{sfx}" for sfx in _JS_PROBE_SUFFIXES]
        for cand in cands:
            rel = self._existing(cand)
            if rel:
                return rel
        return None

    def _existing(self, rel: Path) -> str | None:
        norm = os.path.normpath(str(rel)).replace("\\", "/")
        if norm.startswith("../") or norm == "..":
            return None
        try:
            if contained_file(self.root, norm) is None:
                return None
        except (OSError, ValueError):
            return None
        return norm


# --- GraphQL SDL scoping (#139) --------------------------------------------

_GRAPHQL_EXTS = {".graphql", ".gql"}
_GRAPHQL_CODE_EXTS = JS_TS_SUFFIXES | {".py", ".go", ".rb"}
_GRAPHQL_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", "vendor"}
_GRAPHQL_MAX_DEPTH = 6
_GRAPHQL_MAX_FILES = 2000

# One field definition: `name(args): ReturnType [@directives]`.
# (?<!\w) + possessive \w++: never restart mid-word, so a long word can't
# trigger quadratic backtracking (#236).
_GRAPHQL_FIELD_RE = re.compile(
    r"(?<!\w)(?P<name>\w++)\s*+(?:\((?P<args>[^)]*+)\))?\s*+:\s*(?P<rest>[^\n]*)"
)
# `schema { query: RootQuery  mutation: RootMutation }` custom root types.
_GRAPHQL_SCHEMA_BLOCK_RE = re.compile(r"schema\s*\{(?P<body>[^}]*)\}", re.DOTALL)
_GRAPHQL_SCHEMA_ROOT_RE = re.compile(r"\b(query|mutation)\s*:\s*(\w+)", re.IGNORECASE)
_GRAPHQL_SDL_MARKER_RE = re.compile(r"type\s+(?:Query|Mutation)\b|schema\s*\{")


def _graphql_bola_candidates(root: Path, seen: set) -> list[BolaCandidate]:
    """Scan the repo's GraphQL SDL for id-bearing Query/Mutation fields that
    lack an authorization check (#139). GraphQL fields aren't routes, so
    they're modeled here as ``graphql_field`` surfaces. Authorization can be an
    SDL directive on the field OR an ownership check in the resolver code."""
    files = list(_iter_graphql_files(root))
    # Resolver-side auth: files carrying an ownership marker (`current_user`,
    # `authorize`, …). A field defined as a resolver in such a file is treated
    # as authorized even without an SDL directive.
    auth_resolver_texts = [text for _rel, text in files if _GRAPHQL_RESOLVER_AUTH.search(text)]

    candidates: list[BolaCandidate] = []
    for rel, text in files:
        for type_name, method in _graphql_root_types(text).items():
            for body in _graphql_type_bodies(text, type_name):
                for field in _GRAPHQL_FIELD_RE.finditer(body):
                    name = field.group("name")
                    args = field.group("args") or ""
                    rest = field.group("rest") or ""
                    arg_id = _graphql_id_arg(args)
                    if arg_id is None:
                        continue
                    # Suppress when an SDL directive OR a resolver enforces auth.
                    if _GRAPHQL_AUTH_DIRECTIVE_RE.search(args + " " + rest):
                        continue
                    if _graphql_resolver_authorizes(name, auth_resolver_texts):
                        continue
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


def _graphql_root_types(text: str) -> dict[str, str]:
    """Map GraphQL root type names → method (`QUERY`/`MUTATION`). Includes the
    conventional `Query`/`Mutation` plus any custom roots from a `schema {…}`
    declaration (`schema { query: RootQuery }`)."""
    roots = {"Query": "QUERY", "Mutation": "MUTATION"}
    schema = _GRAPHQL_SCHEMA_BLOCK_RE.search(text)
    if schema:
        for op, type_name in _GRAPHQL_SCHEMA_ROOT_RE.findall(schema.group("body")):
            roots[type_name] = "MUTATION" if op.lower() == "mutation" else "QUERY"
    return roots


def _graphql_type_bodies(text: str, type_name: str):
    """Yield the field-block body of each `type <type_name> { … }` (SDL field
    blocks don't nest braces, so a non-greedy match to the first `}` works)."""
    pattern = re.compile(
        r"(?:extend\s+)?type\s+" + re.escape(type_name) + r"\b[^{]*\{(.*?)\}",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        yield match.group(1)


def _graphql_resolver_authorizes(field_name: str, auth_resolver_texts: list[str]) -> bool:
    """True if the field is defined as a resolver (`name(` / `name:`) in a file
    that also contains an ownership marker — i.e. auth lives in the resolver."""
    resolver_ref = re.compile(r"\b" + re.escape(field_name) + r"\s*[(:]")
    return any(resolver_ref.search(text) for text in auth_resolver_texts)


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


def _iter_graphql_files(root: Path):
    """Yield ``(rel_path, text)`` for files relevant to GraphQL authz: `.graphql`
    / `.gql` files, and code files that either contain SDL (`type Query`, a
    `schema {…}`) or an ownership marker (candidate resolver). Test/fixture and
    vendored files are excluded per the repo's source-quality policy (#139)."""
    count = 0

    def walk(directory: Path, depth: int):
        nonlocal count
        try:
            entries = sorted(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            if count >= _GRAPHQL_MAX_FILES:
                return
            if entry.name in _GRAPHQL_SKIP_DIRS or is_unsafe_link(root, entry):
                continue
            if entry.is_dir():
                if depth < _GRAPHQL_MAX_DEPTH:
                    yield from walk(entry, depth + 1)
                continue
            suffix = entry.suffix.lower()
            if suffix not in _GRAPHQL_EXTS and suffix not in _GRAPHQL_CODE_EXTS:
                continue
            rel = _norm(str(entry.relative_to(root)))
            if is_test_file(rel) or is_vendored_file(rel):
                continue
            try:
                if entry.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = entry.read_text(encoding="utf-8", errors="ignore")
            except (OSError, ValueError):
                continue
            count += 1
            if suffix in _GRAPHQL_CODE_EXTS and not (
                _GRAPHQL_SDL_MARKER_RE.search(text) or _GRAPHQL_RESOLVER_AUTH.search(text)
            ):
                continue
            yield rel, text

    yield from walk(root, 1)


def _norm(rel: str) -> str:
    return rel.replace("\\", "/")


def _module_key(rel: str) -> str:
    """Directory of the file — a coarse 'same module' bucket."""
    norm = _norm(rel)
    return norm.rsplit("/", 1)[0] if "/" in norm else ""


__all__ = ["AUTHN_MARKERS", "OBJECT_AUTHZ_MARKERS", "ROLE_MARKERS", "analyze_authz", "find_bfla_routes"]
