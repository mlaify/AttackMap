"""Per-language taint source, sanitizer and guard catalogs (#239).

The intra-procedural flow pass (:mod:`attackmap.taint_flow`) marks a local
variable tainted when the right-hand side of its assignment matches one of the
**sources** below, then follows simple assignments to the sink. A
**sanitizer** neutralizes the value only when it wraps the tainted value on
the way to the sink (``u = secure_filename(u)``), and a **guard** only when it
is an early-exit (or enclosing) check on a variable derived from the same
source (``if ip.is_private: abort(400)``). Nothing here is file-granular.

Every entry is a ``(label, compiled-regex[, weight])`` tuple so that
``tests/test_regex_budget.py`` auto-discovers and budget-checks each pattern.

Source weights:

- ``"high"`` — attacker-controlled request input (query, body, path params,
  headers, cookies, uploaded filenames, queue/event payloads). Satisfies the
  request-taint gate on SSRF / SSTI / path / redirect / NoSQL sinks.
- ``"low"`` — process environment and argv. Recorded on a chain as its source
  when nothing stronger reaches the sink, but never satisfies the gate: an
  operator-set env var is not attacker input for a web route.

To extend: add a tuple under the language. Keep patterns specific (a member
access on a request-shaped receiver, not a bare identifier) and linear — no
nested quantifiers.
"""

from __future__ import annotations

import re

# Language keys used throughout the flow pass.
PY, JS, GO, PHP, JAVA = "python", "js", "go", "php", "java"

_LANG_BY_SUFFIX = {
    ".py": PY,
    ".js": JS, ".jsx": JS, ".mjs": JS, ".cjs": JS, ".ts": JS, ".tsx": JS, ".mts": JS, ".cts": JS,
    ".go": GO,
    ".php": PHP,
    ".java": JAVA,
}


def lang_for_suffix(suffix: str) -> str | None:
    """The flow-pass language for a file suffix, or None if unsupported."""
    return _LANG_BY_SUFFIX.get(suffix.lower())


# --- Sources -----------------------------------------------------------------
# (kind, pattern, weight). Python patterns are applied with ``re.match`` to the
# source text of an expression node (so they are anchored at the expression
# start); the other languages are searched in statement text with string
# literals blanked out.

_AW = r"(?:await\s+)?"

SOURCES: dict[str, tuple[tuple[str, re.Pattern[str], str], ...]] = {
    PY: (
        ("query", re.compile(_AW + r"request\.(?:args|GET|query_params|query_string|values)\b"), "high"),
        ("body", re.compile(_AW + r"request\.(?:form|json|data|POST|body|get_json|get_data|stream|media)\b"), "high"),
        ("upload_filename", re.compile(_AW + r"request\.(?:files|FILES)\b"), "high"),
        ("header", re.compile(_AW + r"request\.(?:headers|META|environ)\b"), "high"),
        ("cookie", re.compile(_AW + r"request\.(?:cookies|COOKIES)\b"), "high"),
        ("path_param", re.compile(_AW + r"request\.(?:view_args|path_params|match_info|path|full_path|url)\b"), "high"),
        # aiohttp / falcon / starlette style `req`
        ("query", re.compile(_AW + r"req\.(?:params|query|query_params|get_param\w*|rel_url)\b"), "high"),
        ("body", re.compile(_AW + r"req\.(?:media|json|text|post|content|stream|form)\b"), "high"),
        ("header", re.compile(_AW + r"req\.(?:headers|get_header)\b"), "high"),
        ("cookie", re.compile(_AW + r"req\.cookies\b"), "high"),
        ("path_param", re.compile(_AW + r"req\.(?:match_info|path_params)\b"), "high"),
        # AWS Lambda / API Gateway events and queue messages
        (
            "body",
            re.compile(
                r"event\s*(?:\[\s*|\.get\s*\(\s*)[\"'](?:body|queryStringParameters|pathParameters|headers|multiValueQueryStringParameters)[\"']"
            ),
            "high",
        ),
        ("message", re.compile(r"(?:message|msg|record)\s*\[\s*[\"'](?:body|data|payload|value)[\"']"), "high"),
        ("message", re.compile(r"(?:message|msg)\.(?:value|body|data|payload)\b"), "high"),
        ("env", re.compile(r"os\.(?:environ|getenv)\b"), "low"),
        ("argv", re.compile(r"sys\.argv\b"), "low"),
    ),
    JS: (
        ("query", re.compile(r"\breq(?:uest)?\s*\.\s*query\b"), "high"),
        ("query", re.compile(r"\bctx\s*\.\s*(?:request\s*\.\s*)?query(?:string)?\b"), "high"),
        ("query", re.compile(r"\bsearchParams\s*\.\s*get(?:All)?\s*\("), "high"),
        ("body", re.compile(r"\breq(?:uest)?\s*\.\s*body\b"), "high"),
        ("body", re.compile(r"\bctx\s*\.\s*request\s*\.\s*body\b"), "high"),
        ("body", re.compile(r"\bawait\s+req(?:uest)?\s*\.\s*(?:json|formData|text)\s*\("), "high"),
        ("path_param", re.compile(r"\breq(?:uest)?\s*\.\s*params\b"), "high"),
        ("path_param", re.compile(r"\bctx\s*\.\s*params\b"), "high"),
        ("path_param", re.compile(r"\breq\s*\.\s*(?:path|originalUrl|url)\b"), "high"),
        ("header", re.compile(r"\breq(?:uest)?\s*\.\s*headers\b"), "high"),
        ("header", re.compile(r"\breq\s*\.\s*(?:get|header)\s*\("), "high"),
        ("header", re.compile(r"\bctx\s*\.\s*(?:headers|get\s*\()"), "high"),
        ("cookie", re.compile(r"\breq(?:uest)?\s*\.\s*(?:cookies|signedCookies)\b"), "high"),
        ("cookie", re.compile(r"\bctx\s*\.\s*cookies\s*\.\s*get\s*\("), "high"),
        ("upload_filename", re.compile(r"\breq\s*\.\s*files?\b"), "high"),
        ("message", re.compile(r"\b(?:message|msg)\s*\.\s*(?:value|body|content)\b"), "high"),
        ("env", re.compile(r"\bprocess\s*\.\s*env\b"), "low"),
        ("argv", re.compile(r"\bprocess\s*\.\s*argv\b"), "low"),
    ),
    GO: (
        ("query", re.compile(r"\b\w+\.URL\.(?:Query\s*\(\s*\)|RawQuery)"), "high"),
        ("query", re.compile(r"\b(?:c|ctx)\.(?:Query|DefaultQuery|QueryParam|QueryArray|GetQuery)\s*\("), "high"),
        ("body", re.compile(r"\b\w+\.(?:FormValue|PostFormValue)\s*\("), "high"),
        ("body", re.compile(r"\b(?:r|req|request)\.(?:Body|Form|PostForm|MultipartForm)\b"), "high"),
        ("body", re.compile(r"\b(?:c|ctx)\.(?:PostForm|DefaultPostForm|GetRawData|Body)\s*\("), "high"),
        ("path_param", re.compile(r"\bmux\.Vars\s*\("), "high"),
        ("path_param", re.compile(r"\bchi\.URLParam\s*\("), "high"),
        ("path_param", re.compile(r"\b(?:c|ctx)\.(?:Param|Params)\s*\("), "high"),
        ("path_param", re.compile(r"\b(?:r|req|request)\.(?:URL\.Path|RequestURI|PathValue\s*\()"), "high"),
        ("header", re.compile(r"\b(?:r|req|request)\.Header\.(?:Get|Values)\s*\("), "high"),
        ("header", re.compile(r"\b(?:c|ctx)\.(?:GetHeader|Get)\s*\("), "high"),
        ("cookie", re.compile(r"\b(?:r|req|request)\.Cookies?\s*\("), "high"),
        ("cookie", re.compile(r"\b(?:c|ctx)\.Cookie\s*\("), "high"),
        ("upload_filename", re.compile(r"\b\w+\.FormFile\s*\("), "high"),
        ("env", re.compile(r"\bos\.(?:Getenv|LookupEnv|Environ)\s*\("), "low"),
        ("argv", re.compile(r"\bos\.Args\b|\bflag\.(?:Arg|Args)\s*\("), "low"),
    ),
    PHP: (
        ("query", re.compile(r"\$_GET\b"), "high"),
        ("body", re.compile(r"\$_(?:POST|REQUEST)\b"), "high"),
        ("body", re.compile(r"php://input"), "high"),
        ("cookie", re.compile(r"\$_COOKIE\b"), "high"),
        ("upload_filename", re.compile(r"\$_FILES\b"), "high"),
        ("header", re.compile(r"\$_SERVER\s*\[\s*['\"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PATH_INFO|PHP_SELF)['\"]"), "high"),
        # Laravel / Symfony request objects
        (
            "body",
            re.compile(r"\$request\s*->\s*(?:input|get|post|all|only|json|getContent|validated)\s*\("),
            "high",
        ),
        ("query", re.compile(r"\$request\s*->\s*(?:query)\b"), "high"),
        ("header", re.compile(r"\$request\s*->\s*(?:header|headers)\b"), "high"),
        ("cookie", re.compile(r"\$request\s*->\s*(?:cookie|cookies)\b"), "high"),
        ("path_param", re.compile(r"\$request\s*->\s*(?:route|attributes|getPathInfo|getRequestUri)\b"), "high"),
        ("upload_filename", re.compile(r"\$request\s*->\s*(?:file|files)\b"), "high"),
        ("body", re.compile(r"\$request\s*->\s*request\s*->\s*get\s*\("), "high"),
        ("env", re.compile(r"\bgetenv\s*\(|\$_ENV\b"), "low"),
        ("argv", re.compile(r"\$argv\b"), "low"),
    ),
    JAVA: (
        (
            "query",
            re.compile(r"\b\w+\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|getQueryString)\s*\("),
            "high",
        ),
        (
            "body",
            re.compile(
                r"\b(?:request|req|httpRequest|servletRequest|httpServletRequest)\s*\.\s*"
                r"(?:getInputStream|getReader|getPart|getParts)\s*\("
            ),
            "high",
        ),
        ("path_param", re.compile(r"\b\w+\s*\.\s*(?:getRequestURI|getPathInfo|getServletPath)\s*\("), "high"),
        (
            "header",
            re.compile(r"\b(?:request|req|httpRequest|servletRequest|httpServletRequest)\s*\.\s*getHeaders?\s*\("),
            "high",
        ),
        ("cookie", re.compile(r"\b\w+\s*\.\s*getCookies\s*\(\s*\)"), "high"),
        ("env", re.compile(r"\bSystem\s*\.\s*(?:getenv|getProperty)\s*\("), "low"),
    ),
}

# Handler parameters bound from the request by a framework annotation /
# decorator (Spring, JAX-RS, NestJS). The parameter name follows the
# annotation; the flow pass extracts it procedurally.
PARAM_ANNOTATIONS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    JAVA: (
        ("query", re.compile(r"@(?:RequestParam|QueryParam|MatrixParam)\b")),
        ("path_param", re.compile(r"@(?:PathVariable|PathParam)\b")),
        ("body", re.compile(r"@(?:RequestBody|ModelAttribute|RequestPart|FormParam|BeanParam)\b")),
        ("header", re.compile(r"@(?:RequestHeader|HeaderParam)\b")),
        ("cookie", re.compile(r"@(?:CookieValue|CookieParam)\b")),
    ),
    JS: (
        ("query", re.compile(r"@Query\s*\(")),
        ("path_param", re.compile(r"@Param\s*\(")),
        ("body", re.compile(r"@Body\s*\(")),
        ("header", re.compile(r"@Headers\s*\(")),
        ("upload_filename", re.compile(r"@UploadedFiles?\s*\(")),
    ),
}

# Python route decorators (the decorator call's final attribute name, matched
# on the AST) — a decorated function is a request handler and its
# (non-framework) parameters are request-bound: path params, FastAPI query /
# body params.
PY_ROUTE_DECORATOR_NAMES = frozenset(
    {"route", "get", "post", "put", "patch", "delete", "head", "options", "api_route", "websocket"}
)
# Parameters that are framework plumbing, not attacker data.
PY_PLUMBING_PARAMS = frozenset(
    {"self", "cls", "request", "req", "db", "session", "response", "background_tasks", "current_user", "user"}
)
# Annotations that coerce (int / UUID / date) or mark plumbing — such a
# parameter is not an injectable string.
PY_SAFE_ANNOTATION = re.compile(
    r"\b(?:int|float|bool|UUID|uuid\.UUID|datetime|date|time|Decimal|PositiveInt|NonNegativeInt|conint|"
    r"Request|Response|Session|AsyncSession|BackgroundTasks|WebSocket|HTTPConnection|Depends|Security)\b"
)
PY_SAFE_DEFAULT = re.compile(r"\b(?:Depends|Security)\s*\(")
PY_SCALAR_ANNOTATION = re.compile(r"\b(?:str|list|List|Optional|Query|Path)\b")


# --- Sanitizers (flow-bound wrappers) ----------------------------------------
# A sanitizer counts only when the tainted value passes *through* the call on
# the way to the sink: ``safe = shlex.quote(host)`` then ``run(... safe ...)``,
# or the wrapper inline in the sink argument. Each pattern matches the callee
# name up to (and including) its opening paren.

SANITIZERS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "subprocess_shell": (
        ("shlex.quote", re.compile(r"\bshlex\.quote\s*\(")),
        ("pipes.quote", re.compile(r"\bpipes\.quote\s*\(")),
        ("escapeshellarg/escapeshellcmd", re.compile(r"\b(?:escapeshellarg|escapeshellcmd)\s*\(")),
        ("shell-escape", re.compile(r"\b(?:shellEscape|shellescape|shellQuote\.quote)\s*\(")),
    ),
    "sql_execute": (
        ("mysqli_real_escape_string", re.compile(r"\bmysqli_real_escape_string\s*\(")),
        ("pg_escape_*", re.compile(r"\bpg_escape_(?:string|literal|identifier)\s*\(")),
        ("PDO::quote", re.compile(r"->\s*quote\s*\(")),
        ("sql escape()", re.compile(r"\b(?:mysql|connection|conn|pool|SqlString)\s*\.\s*escape(?:Id)?\s*\(")),
    ),
    "dynamic_open": (
        ("werkzeug.secure_filename", re.compile(r"\bsecure_filename\s*\(")),
        ("os.path.basename", re.compile(r"\bos\.path\.basename\s*\(")),
        ("path.basename", re.compile(r"\bpath\s*\.\s*basename\s*\(")),
        ("filepath.Base", re.compile(r"\bfilepath\.Base\s*\(")),
        ("basename()", re.compile(r"(?<![\w.>$])basename\s*\(")),
        ("FilenameUtils.getName", re.compile(r"\bFilenameUtils\s*\.\s*getName\s*\(")),
    ),
    # Only a real escaper of the template *source*. `re.escape` / `html.escape`
    # are deliberately absent (#239): neither neutralizes `{{ ... }}`, and their
    # presence elsewhere in a file used to silence real SSTI chains.
    "ssti": (
        ("markupsafe.escape", re.compile(r"\b(?:markupsafe|Markup)\.escape\s*\(|(?<![\w.])escape\s*\(")),
        ("bleach.clean", re.compile(r"\bbleach\.clean\s*\(")),
    ),
    "nosql_injection": (
        ("mongo-sanitize", re.compile(r"\b(?:mongoSanitize|mongo_sanitize|sanitize)\s*\(")),
    ),
    "open_redirect": (
        ("url_for", re.compile(r"\burl_for\s*\(")),
    ),
}

# Type coercions neutralize every string-injection kind: an int can't carry
# a payload. Applied for all sink kinds.
CAST_SANITIZERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("int() cast", re.compile(r"(?<![\w.])(?:int|float|bool)\s*\(")),
    ("UUID cast", re.compile(r"\b(?:uuid\.)?UUID\s*\(|\bUUID\s*\.\s*fromString\s*\(")),
    (
        "Java numeric parse",
        re.compile(r"\b(?:Integer|Long|Short|Double|Float)\s*\.\s*(?:parseInt|parseLong|parseShort|parseDouble|parseFloat|valueOf)\s*\("),
    ),
    ("parseInt/Number cast", re.compile(r"\b(?:parseInt|parseFloat|Number)\s*\(")),
    ("strconv cast", re.compile(r"\bstrconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\s*\(")),
    ("intval cast", re.compile(r"\b(?:intval|floatval|boolval)\s*\(|\(\s*(?:int|float)\s*\)\s*\$")),
)


# --- Guards (flow-bound checks dominating the sink) --------------------------
# A guard neutralizes when its condition references a variable derived from
# the same source as the sink argument AND it dominates the sink: either an
# early exit (`if <cond>: abort/return/raise`) before the sink, or an `if`
# whose body contains the sink.

GUARDS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    # SSRF needs an actual address-class or allow-list decision — the mere
    # presence of `ipaddress.ip_address(` (often just logging) is not enough.
    "ssrf": (
        (
            "private/loopback/link-local address check",
            re.compile(
                r"\.is_(?:private|loopback|link_local|reserved|multicast|unspecified|global)\b"
                r"|\.Is(?:Private|Loopback|LinkLocalUnicast|LinkLocalMulticast|Unspecified|GlobalUnicast)\s*\("
                r"|\.is(?:SiteLocal|Loopback|LinkLocal|AnyLocal)Address\s*\("
            ),
        ),
        ("outbound URL allow-list", re.compile(r"\b(?:is_allowed_url|is_safe_url|isAllowedUrl|isSafeUrl)\s*\(")),
    ),
    "open_redirect": (
        ("is_safe_url", re.compile(r"\bis_safe_url\s*\(")),
        ("url_has_allowed_host_and_scheme", re.compile(r"\burl_has_allowed_host_and_scheme\s*\(")),
        ("relative-path check", re.compile(r"\.startswith\s*\(\s*[\"']/[\"']|\.startsWith\s*\(\s*[\"']/[\"']")),
    ),
    "dynamic_open": (
        (
            "path containment check",
            re.compile(r"\b(?:startswith|startsWith|HasPrefix|str_starts_with|is_relative_to|commonpath)\s*\("),
        ),
    ),
    "subprocess_shell": (),
    "sql_execute": (),
}

# Guards valid for every sink kind: an explicit allow-list membership test or a
# full-match regex validation of the value.
GENERIC_GUARDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "allow-list check",
        re.compile(
            r"\b(?:ALLOWED_\w+|ALLOW_?LIST\w*|allowed_\w+|allowlist\w*|allowList\w*|whitelist\w*|"
            r"allowedHosts|allowedDomains|allowedCommands|allowedFiles)\b"
        ),
    ),
    (
        "regex validation",
        re.compile(r"\bre\.fullmatch\s*\(|\bpreg_match\s*\(|\.MatchString\s*\(|\.matches\s*\(\s*\"\^"),
    ),
)

# Tokens that make a guard's branch an early exit.
EARLY_EXIT = re.compile(
    r"\b(?:return|throw|raise|abort|exit|die|panic|continue|break)\b"
    r"|\bhttp\.Error\s*\(|\.sendStatus\s*\(|\.AbortWith\w*\s*\(|\bHttpResponseBadRequest\b"
)


def sanitizer_patterns(kind: str) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Flow-bound wrappers that neutralize ``kind`` (kind-specific + casts)."""
    return SANITIZERS.get(kind, ()) + CAST_SANITIZERS


def guard_patterns(kind: str) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Dominating checks that neutralize ``kind`` (kind-specific + generic)."""
    return GUARDS.get(kind, ()) + GENERIC_GUARDS


ALL_SANITIZER_KINDS: tuple[str, ...] = (
    "sql_execute",
    "subprocess_shell",
    "eval",
    "exec",
    "dynamic_open",
    "unsafe_deserialization",
    "ssti",
    "ssrf",
    "nosql_injection",
    "open_redirect",
)
