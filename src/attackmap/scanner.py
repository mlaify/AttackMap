from __future__ import annotations

import base64
import binascii
import math
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .progress import ScanProgress

from .anomalies import find_anomalies
from .authz import analyze_authz
from .crypto import find_crypto_weaknesses
from .sbom import analyze_sbom
from .srcpaths import is_test_file
from .weaknesses import find_code_weaknesses
from .webhardening import find_web_hardening_issues
from .sdk.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint
from .taint import analyze_taint

# Scanner responsibilities are intentionally generic-only:
# - file walking and suffix filtering
# - route extraction
# - external-call extraction
# - datastore/auth/secret hint extraction
# Ecosystem overlays (for example node-service and atproto service/protocol hints)
# must be emitted by specialized analyzers, not by this module.

CODE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

FASTAPI_ROUTER_PATTERN = re.compile(
    r"(\w+)\s*=\s*APIRouter\(\s*(?:[^)]*?\bprefix\s*=\s*['\"]([^'\"]*)['\"])?",
    re.IGNORECASE | re.DOTALL,
)
FASTAPI_INCLUDE_ROUTER_PATTERN = re.compile(
    r"(\w+)\.include_router\(\s*(\w+)(?:\s*,\s*prefix\s*=\s*['\"]([^'\"]*)['\"])?",
    re.IGNORECASE,
)
FASTAPI_DECORATOR_PATTERN = re.compile(
    r"@(\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
FASTAPI_API_ROUTE_PATTERN = re.compile(
    r"@(\w+)\.api_route\(\s*['\"]([^'\"]+)['\"](?P<args>.*?)\)",
    re.IGNORECASE | re.DOTALL,
)
FLASK_BLUEPRINT_PATTERN = re.compile(
    r"(\w+)\s*=\s*Blueprint\(\s*['\"][^'\"]+['\"]\s*,\s*[^,]+(?:,\s*url_prefix\s*=\s*['\"]([^'\"]*)['\"])?",
    re.IGNORECASE | re.DOTALL,
)
FLASK_REGISTER_BLUEPRINT_PATTERN = re.compile(
    r"(\w+)\.register_blueprint\(\s*(\w+)(?:\s*,\s*url_prefix\s*=\s*['\"]([^'\"]*)['\"])?",
    re.IGNORECASE,
)
FLASK_ROUTE_PATTERN = re.compile(
    r"@(\w+)\.route\(\s*['\"]([^'\"]+)['\"](?P<args>.*?)\)",
    re.IGNORECASE | re.DOTALL,
)
EXPRESS_DIRECT_ROUTE_PATTERN = re.compile(
    r"\b(\w+)\.(get|post|put|delete|patch|options|head|all)\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
EXPRESS_CHAIN_ROUTE_PATTERN = re.compile(
    r"\b(\w+)\.route\(\s*['\"]([^'\"]+)['\"]\s*\)(?P<chain>[\s\S]*?)(?=(?:\n\s*\w+\.)|\Z)",
    re.IGNORECASE,
)
EXPRESS_USE_PATTERN = re.compile(
    r"\b(\w+)\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)\s*\)",
    re.IGNORECASE,
)
METHOD_LIST_PATTERN = re.compile(r"['\"](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|ALL)['\"]", re.IGNORECASE)

EXTERNAL_CALL_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"),
    re.compile(r"axios\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"),
    re.compile(r"fetch\(['\"]([^'\"]+)['\"]"),
]

DB_KEYWORDS = {
    "postgres": "postgresql",
    "psycopg": "postgresql",
    "sqlalchemy": "sql",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "redis": "redis",
    "sqlite": "sqlite",
    "mysql": "mysql",
}

DB_PATTERNS = [
    # SQL — SQLAlchemy / raw / Django / Prisma / Drizzle
    (re.compile(r"create_engine\(\s*['\"](?:postgresql|mysql|sqlite|mssql|oracle)\+?", re.IGNORECASE), "sql"),
    (re.compile(r"create_async_engine\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bsessionmaker\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bAsyncSession\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bdeclarative_base\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"new\s+PrismaClient\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bdrizzle\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bknex\s*\(", re.IGNORECASE), "sql"),
    # Raw SQL usage — cursor.execute with a SQL verb literal is a strong
    # signal that raw SQL (not an ORM) is in play, which matters for
    # injection review. #2.
    (re.compile(r"\.execute\(\s*['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", re.IGNORECASE), "sql"),
    (re.compile(r"\.executemany\(\s*['\"]", re.IGNORECASE), "sql"),
    # PostgreSQL
    (re.compile(r"psycopg(?:2|3)?\.connect\(", re.IGNORECASE), "postgresql"),
    (re.compile(r"\basyncpg\.connect\(", re.IGNORECASE), "postgresql"),
    (re.compile(r"new\s+Pool\(", re.IGNORECASE), "postgresql"),
    # SQLite
    (re.compile(r"sqlite3\.connect\(", re.IGNORECASE), "sqlite"),
    (re.compile(r"\bbetter-sqlite3\b|new\s+SQLite3?\b", re.IGNORECASE), "sqlite"),
    # MySQL
    (re.compile(r"\bmysql\.connector\.connect\(", re.IGNORECASE), "mysql"),
    (re.compile(r"\bMySQLdb\.connect\(", re.IGNORECASE), "mysql"),
    (re.compile(r"\baiomysql\.connect\(", re.IGNORECASE), "mysql"),
    # MongoDB
    (re.compile(r"(?:AsyncIOMotorClient|MongoClient)\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bpymongo\.MongoClient\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"mongoose\.connect\(", re.IGNORECASE), "mongodb"),
    # Redis
    (re.compile(r"redis\.(?:Redis|StrictRedis)\(", re.IGNORECASE), "redis"),
    (re.compile(r"\bredis\.from_url\(", re.IGNORECASE), "redis"),
    (re.compile(r"\baioredis\b|from\s+redis\s+import", re.IGNORECASE), "redis"),
    (re.compile(r"redis\.createClient\(", re.IGNORECASE), "redis"),
]

# Kept intentionally short — noisy naked words (`session`, `password`,
# `token`, `mfa`, `bearer`) were dropped in #2. They fired across
# unrelated code and turned the file-level auth-signal set into
# indistinguishable noise (see Bluesky FINDINGS.md §55). Specific
# compound patterns in AUTH_PATTERNS below carry the real signal.
AUTH_KEYWORDS = [
    "jwt",
    "oauth",
    "auth0",
    "apikey",
    "api_key",
]

AUTH_PATTERNS = [
    # Decorator-based
    (re.compile(r"@login_required\b", re.IGNORECASE), "login_required"),
    (re.compile(r"@jwt_required\b", re.IGNORECASE), "jwt"),
    (re.compile(r"@UseGuards\("), "auth_guard"),
    # JWT library calls — jwt.decode / encode / verify / sign
    (re.compile(r"\bjwt\.(?:decode|encode|verify|sign)\(", re.IGNORECASE), "jwt"),
    (re.compile(r"\bjsonwebtoken\b", re.IGNORECASE), "jwt"),
    (re.compile(r"\bPyJWT\b"), "jwt"),
    # OAuth / OIDC library forms
    (re.compile(r"OAuth2PasswordBearer\(", re.IGNORECASE), "oauth"),
    (re.compile(r"\bauthlib\.\w+", re.IGNORECASE), "oauth"),
    # FastAPI Depends-based auth
    (re.compile(r"Depends\(\s*(?:oauth2_scheme|get_current_user|current_user|verify_token)\s*\)", re.IGNORECASE), "depends_auth"),
    # Authorization header access — Python, JS, Node
    (re.compile(r"request\.authorization\b", re.IGNORECASE), "authorization"),
    (re.compile(r"request\.headers\.get\(\s*['\"]authorization['\"]", re.IGNORECASE), "authorization"),
    (re.compile(r"req\.headers\[\s*['\"]authorization['\"]", re.IGNORECASE), "authorization"),
    (re.compile(r"req\.get\(\s*['\"]authorization['\"]", re.IGNORECASE), "authorization"),
    (re.compile(r"Authorization['\"]?\s*\]", re.IGNORECASE), "authorization"),
    # Bearer-token access (context, not naked word)
    (re.compile(r"\bBearer\s+\$\{?[a-z_]"), "bearer_token"),
    (re.compile(r"['\"]Bearer\s"), "bearer_token"),
    # Middleware / guard naming conventions
    (re.compile(r"passport\.authenticate\(", re.IGNORECASE), "passport"),
    (re.compile(r"\bpassport\.use\(", re.IGNORECASE), "passport"),
    (re.compile(r"\b(?:verify|require)Token\s*\(", re.IGNORECASE), "verify_token"),
    (re.compile(r"\bisAuthenticated\s*\(", re.IGNORECASE), "auth_middleware"),
    (re.compile(r"\bensureLoggedIn\s*\(", re.IGNORECASE), "auth_middleware"),
    (re.compile(r"\brequire(?:Auth|Login)\s*\(", re.IGNORECASE), "auth_middleware"),
    (re.compile(r"\bwithAuth\s*[(<]", re.IGNORECASE), "auth_middleware"),
    (re.compile(r"\bauthMiddleware\b", re.IGNORECASE), "auth_middleware"),
    (re.compile(r"\bauthGuard\b|\bAuthGuard\b"), "auth_guard"),
    # Session-based auth — specific compound tokens, not the bare word "session"
    (re.compile(r"\bexpress-session\b|require\(['\"]express-session['\"]"), "session_middleware"),
    (re.compile(r"\breq\.session\.\w"), "session_state"),
    (re.compile(r"\brequest\.session\.\w"), "session_state"),
    (re.compile(r"\bcookie-session\b"), "session_middleware"),
    (re.compile(r"\bflask_login\b|from\s+flask_login\s+import"), "session_middleware"),
    (re.compile(r"\bdjango\.contrib\.auth\b"), "session_middleware"),
    # MFA / 2FA — compound tokens only
    (re.compile(r"\bmfa_required\b|\btwo_factor\b|\btotp_verify\b", re.IGNORECASE), "mfa"),
    # Password-handling — compound tokens only
    (re.compile(r"\bpassword_hash\b|\bpassword_reset\b|\bcheck_password\b", re.IGNORECASE), "password_flow"),
    (re.compile(r"\bbcrypt\.(?:hash|compare)\s*\(", re.IGNORECASE), "password_flow"),
    (re.compile(r"\bargon2\b"), "password_flow"),
]

SECRET_PATTERNS = [
    re.compile(r"os\.getenv\(['\"]([^'\"]*(SECRET|TOKEN|KEY|PASSWORD)[^'\"]*)['\"]", re.IGNORECASE),
    re.compile(r"process\.env\.([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Hard-coded secret literals (#39). Each entry is (regex, kind).
# The regex captures the FULL secret in group 0 or its main group; the
# `kind` becomes SecretHint.kind and the finder reads it as the display
# name. Values are redacted before being included in evidence_text — the
# raw secret must never appear in reports.
# ---------------------------------------------------------------------------

HARDCODED_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "aws_access_key"),
    (re.compile(r"\b(ASIA[0-9A-Z]{16})\b"), "aws_temporary_key"),
    # GitHub — classic PATs and the newer prefixes (fine-grained tokens,
    # OAuth apps, server tokens, refresh tokens).
    (re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"), "github_pat"),
    (re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b"), "github_oauth_token"),
    (re.compile(r"\b(ghu_[A-Za-z0-9]{36,})\b"), "github_user_token"),
    (re.compile(r"\b(ghs_[A-Za-z0-9]{36,})\b"), "github_server_token"),
    (re.compile(r"\b(ghr_[A-Za-z0-9]{36,})\b"), "github_refresh_token"),
    # Slack bot / user / app tokens
    (re.compile(r"\b(xox[bpsare]-[0-9A-Za-z-]{10,})\b"), "slack_token"),
    # Stripe live / test keys
    (re.compile(r"\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,})\b"), "stripe_key"),
    # SendGrid
    (re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), "sendgrid_key"),
    # Mailgun
    (re.compile(r"\b(key-[a-f0-9]{32})\b"), "mailgun_key"),
    # Twilio account SID — AC followed by 32 hex. Narrow enough to avoid
    # false-positives on random 34-char strings starting with AC.
    (re.compile(r"\b(AC[a-f0-9]{32})\b"), "twilio_account_sid"),
    # Google API key — most are 35 chars after AIza; some Cloud variants
    # run slightly longer.
    (re.compile(r"\b(AIza[A-Za-z0-9_-]{35,42})\b"), "google_api_key"),
    # Anthropic API key (long, characteristic prefix)
    (re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{40,})\b"), "anthropic_key"),
    # PEM private-key block — match `-----BEGIN [<algo> ]PRIVATE KEY-----`,
    # covering both bare `-----BEGIN PRIVATE KEY-----` and prefixed forms
    # (`RSA`, `EC`, `DSA`, `OPENSSH`, `ENCRYPTED`). Capture just the header
    # line as evidence; never emit key material.
    (re.compile(r"(-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----)"), "pem_private_key"),
    # JWT — three base64url segments separated by dots, first decoding
    # to a JSON header. Recognized by shape here; verified for shape
    # (base64url + non-trivial length) in the extractor below.
    (re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "jwt"),
]

# Minimum length for the high-entropy fallback. Under this, entropy
# calculations aren't statistically meaningful, and shorter secrets
# tend to be caught by explicit provider patterns anyway.
_ENTROPY_MIN_LENGTH = 32
_ENTROPY_MAX_LENGTH = 256  # very long strings are usually inline assets
_ENTROPY_THRESHOLD = 4.5   # bits per character
# Extracts quoted string literals (single or double quoted) for entropy
# fallback. Kept intentionally narrow: no multi-line strings.
_QUOTED_LITERAL = re.compile(r"['\"]([A-Za-z0-9+/_=-]{32,256})['\"]")


_SNIPPET_MAX_CHARS = 160


def _line_of(content: str, offset: int) -> int:
    """1-indexed line number for a character offset within content."""
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    """Return the line containing `offset`, stripped and length-capped."""
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def should_scan(path: Path) -> bool:
    if path.name.startswith("."):
        return False
    if any(part in {"node_modules", ".git", ".venv", "dist", "build"} for part in path.parts):
        return False
    return path.suffix in CODE_EXTENSIONS


def should_scan_with_suffixes(path: Path, suffixes: set[str] | None = None) -> bool:
    if not should_scan(path):
        return False
    if suffixes is None:
        return True
    return path.suffix in suffixes


def _normalize_path(path: str) -> str:
    """Ensure path is non-empty and starts with a single forward slash.

    This guarantees consistent path output across frameworks: FastAPI, Flask,
    and Express can all be invoked with or without a leading ``/``, but
    downstream consumers (path joining, prefix concatenation, attack-surface
    display) rely on a canonical ``/foo/bar`` shape.
    """
    cleaned = (path or "").strip()
    if not cleaned:
        return "/"
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    # Collapse runs of slashes so ``//a//b`` -> ``/a/b``.
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    return cleaned


def _join_route_parts(prefix: str, path: str) -> str:
    base = _normalize_path(prefix)
    suffix = _normalize_path(path)

    if base == "/":
        return suffix
    if suffix == "/":
        return base
    return f"{base.rstrip('/')}/{suffix.lstrip('/')}"


def _extract_methods(args: str, default_method: str = "ANY") -> list[str]:
    methods = [match.upper() for match in METHOD_LIST_PATTERN.findall(args)]
    # "ALL" is a non-standard alias sometimes used in API code; normalize it
    # to the canonical Route(method="ANY") sentinel.
    methods = ["ANY" if m == "ALL" else m for m in methods]
    return methods or [default_method]


def _python_route_prefixes(content: str) -> dict[str, str]:
    local_prefixes: dict[str, str] = {}

    for match in FASTAPI_ROUTER_PATTERN.finditer(content):
        local_prefixes[match.group(1)] = match.group(2) or ""

    for match in FLASK_BLUEPRINT_PATTERN.finditer(content):
        local_prefixes[match.group(1)] = match.group(2) or ""

    prefixes = dict(local_prefixes)
    updated = True
    while updated:
        updated = False

        for match in FASTAPI_INCLUDE_ROUTER_PATTERN.finditer(content):
            parent_name, child_name, extra_prefix = match.groups()
            parent_prefix = prefixes.get(parent_name, "")
            child_prefix = local_prefixes.get(child_name, "")
            combined = _join_route_parts(parent_prefix, _join_route_parts(extra_prefix or "", child_prefix))
            if prefixes.get(child_name) != combined:
                prefixes[child_name] = combined
                updated = True

        for match in FLASK_REGISTER_BLUEPRINT_PATTERN.finditer(content):
            parent_name, child_name, extra_prefix = match.groups()
            parent_prefix = prefixes.get(parent_name, "")
            child_prefix = local_prefixes.get(child_name, "")
            combined = _join_route_parts(parent_prefix, _join_route_parts(extra_prefix or "", child_prefix))
            if prefixes.get(child_name) != combined:
                prefixes[child_name] = combined
                updated = True

    return prefixes


def _extract_python_routes(content: str, file: str) -> list[Route]:
    routes: list[Route] = []
    prefixes = _python_route_prefixes(content)

    for match in FASTAPI_DECORATOR_PATTERN.finditer(content):
        router_name, method, route_path = match.groups()
        routes.append(
            Route(
                path=_join_route_parts(prefixes.get(router_name, ""), route_path),
                method=method.upper(),
                file=file,
                line=_line_of(content, match.start()),
            )
        )

    for match in FASTAPI_API_ROUTE_PATTERN.finditer(content):
        router_name, route_path, args = match.group(1), match.group(2), match.group("args")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        line = _line_of(content, match.start())
        for method in _extract_methods(args, default_method="ANY"):
            routes.append(Route(path=full_path, method=method, file=file, line=line))

    for match in FLASK_ROUTE_PATTERN.finditer(content):
        router_name, route_path, args = match.group(1), match.group(2), match.group("args")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        line = _line_of(content, match.start())
        for method in _extract_methods(args, default_method="GET"):
            routes.append(Route(path=full_path, method=method, file=file, line=line))

    return routes


def _express_prefixes(content: str) -> dict[str, str]:
    local_prefixes: dict[str, str] = {}
    prefixes: dict[str, str] = {}

    updated = True
    while updated:
        updated = False
        for match in EXPRESS_USE_PATTERN.finditer(content):
            parent_name, mount_path, child_name = match.groups()
            parent_prefix = prefixes.get(parent_name, "")
            child_prefix = local_prefixes.get(child_name, "")
            local_prefixes[child_name] = child_prefix
            combined = _join_route_parts(parent_prefix, _join_route_parts(mount_path, child_prefix))
            if prefixes.get(child_name) != combined:
                prefixes[child_name] = combined
                updated = True

    return prefixes


def _extract_javascript_routes(content: str, file: str) -> list[Route]:
    routes: list[Route] = []
    prefixes = _express_prefixes(content)

    for match in EXPRESS_DIRECT_ROUTE_PATTERN.finditer(content):
        router_name, method, route_path = match.groups()
        method_normalized = method.upper()
        if method_normalized == "ALL":
            method_normalized = "ANY"
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        routes.append(
            Route(
                path=full_path,
                method=method_normalized,
                file=file,
                line=_line_of(content, match.start()),
            )
        )

    for match in EXPRESS_CHAIN_ROUTE_PATTERN.finditer(content):
        router_name, route_path, chain = match.group(1), match.group(2), match.group("chain")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        chain_offset = match.start("chain")
        for method_match in re.finditer(r"\.(get|post|put|delete|patch|options|head|all)\s*\(", chain, re.IGNORECASE):
            method = method_match.group(1).upper()
            if method == "ALL":
                method = "ANY"
            routes.append(
                Route(
                    path=full_path,
                    method=method,
                    file=file,
                    line=_line_of(content, chain_offset + method_match.start()),
                )
            )

    return routes


def extract_routes(content: str, file: str, suffix: str) -> list[Route]:
    if suffix == ".py":
        return _extract_python_routes(content, file)
    if suffix in {".js", ".ts", ".tsx"}:
        return _extract_javascript_routes(content, file)
    return []


def _append_unique_database_hints(result: ScanResult, relative: str, content: str, lowered: str) -> None:
    seen = {(hint.kind, hint.file) for hint in result.databases}

    for pattern, kind in DB_PATTERNS:
        match = pattern.search(content)
        if match and (kind, relative) not in seen:
            result.databases.append(
                DatabaseHint(
                    kind=kind,
                    file=relative,
                    line=_line_of(content, match.start()),
                    evidence_text=_line_snippet(content, match.start()),
                )
            )
            seen.add((kind, relative))

    for keyword, kind in DB_KEYWORDS.items():
        idx = lowered.find(keyword)
        if idx != -1 and (kind, relative) not in seen:
            result.databases.append(
                DatabaseHint(
                    kind=kind,
                    file=relative,
                    line=_line_of(content, idx),
                    evidence_text=_line_snippet(content, idx),
                )
            )
            seen.add((kind, relative))


def _append_unique_auth_hints(result: ScanResult, relative: str, content: str, lowered: str) -> None:
    seen = {(hint.hint, hint.file) for hint in result.auth_hints}

    for pattern, hint in AUTH_PATTERNS:
        match = pattern.search(content)
        if match and (hint, relative) not in seen:
            result.auth_hints.append(
                AuthHint(
                    hint=hint,
                    file=relative,
                    line=_line_of(content, match.start()),
                    evidence_text=_line_snippet(content, match.start()),
                    confidence=0.85,
                )
            )
            seen.add((hint, relative))

    for keyword in AUTH_KEYWORDS:
        idx = lowered.find(keyword)
        if idx != -1 and (keyword, relative) not in seen:
            result.auth_hints.append(
                AuthHint(
                    hint=keyword,
                    file=relative,
                    line=_line_of(content, idx),
                    evidence_text=_line_snippet(content, idx),
                    confidence=0.5,
                )
            )
            seen.add((keyword, relative))


def scan_repo(
    root: str | Path,
    suffixes: set[str] | None = None,
    progress: "ScanProgress | None" = None,
) -> ScanResult:
    root_path = Path(root).resolve()
    result = ScanResult(root=str(root_path))

    # Materialize the scannable file list first so progress has a total to
    # compute a percentage and ETA against. The extra directory walk is cheap
    # next to reading + regex-scanning each file.
    scan_files = [
        p for p in root_path.rglob("*") if p.is_file() and should_scan_with_suffixes(p, suffixes)
    ]
    if progress is not None:
        progress.begin(len(scan_files))

    for file_path in scan_files:
        if progress is not None:
            progress.advance(str(file_path.relative_to(root_path)))

        result.files_scanned += 1
        language = CODE_EXTENSIONS[file_path.suffix]
        if language not in result.languages:
            result.languages.append(language)

        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        relative = str(file_path.relative_to(root_path))
        file_routes = extract_routes(content, relative, file_path.suffix)
        result.routes.extend(file_routes)

        for pattern in EXTERNAL_CALL_PATTERNS:
            for match in pattern.finditer(content):
                target = match.groups()[-1]
                result.external_calls.append(
                    ExternalCall(
                        target=target,
                        file=relative,
                        line=_line_of(content, match.start()),
                        evidence_text=_line_snippet(content, match.start()),
                    )
                )

        lowered = content.lower()
        _append_unique_database_hints(result, relative, content, lowered)
        _append_unique_auth_hints(result, relative, content, lowered)

        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                result.secret_hints.append(
                    SecretHint(
                        name=match.groups()[0],
                        file=relative,
                        line=_line_of(content, match.start()),
                        evidence_text=_line_snippet(content, match.start()),
                        kind="env_reference",
                    )
                )

        _append_hardcoded_secret_hints(result, relative, content)

        # The weakness passes below are noise in test scaffolding, so skip
        # test/spec files by default (#67; ATTACKMAP_INCLUDE_TESTS opts in).
        if not is_test_file(relative):
            # Insecure crypto / weak randomness (#70). Content is already
            # read, so this rides the per-file pass rather than re-walking.
            result.crypto_weaknesses.extend(find_crypto_weaknesses(content, relative))
            # Web-hardening gaps (#71): CORS, CSRF, cookies, CSP, debug.
            result.web_hardening_issues.extend(find_web_hardening_issues(content, relative))
            # Novel vuln classes (#77): proto pollution, mass assignment, JWT, XXE.
            result.code_weaknesses.extend(find_code_weaknesses(content, relative))

    result.languages.sort()
    # Taint pass runs after regular signal extraction — it needs the
    # route list to know where to seed source flows from (#45). This is the
    # slow tail on big monorepos (import-graph walk), so it gets its own
    # progress stage.
    if progress is not None:
        progress.stage("Taint / data-flow analysis")
    result.taint_chains = analyze_taint(result, root_path)
    # SBOM inventory: direct-dep parse of manifest files (#48, slice 1).
    if progress is not None:
        progress.stage("Dependency inventory (SBOM)")
    result.dependencies = analyze_sbom(root_path)
    # BOLA/IDOR: routes with an id param reaching a datastore with no
    # ownership check nearby (#69). Runs after taint so it can reuse
    # sql_execute reachability.
    if progress is not None:
        progress.stage("Authorization (BOLA/IDOR)")
    result.authz_candidates = analyze_authz(result, root_path)
    # Anomaly / outlier pass (#78): the odd-one-out among sibling routes.
    # Runs last so the full route list is assembled into cohorts.
    if progress is not None:
        progress.stage("Anomaly / outlier detection")
    result.anomalies = find_anomalies(result, root_path)
    if progress is not None:
        progress.done()
    return result


def _redact_secret(value: str) -> str:
    """Show first 4 and last 4 characters of a secret literal, mask the
    middle. Never emit the raw value to reports."""
    if len(value) <= 8:
        return "…"
    return f"{value[:4]}…{value[-4:]}"


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies: dict[str, int] = {}
    for ch in value:
        frequencies[ch] = frequencies.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_secret_candidate(value: str) -> bool:
    """Reject obvious non-secret shapes that would otherwise clear the
    entropy bar (hex hashes in comments, URLs, etc.)."""
    if len(value) < _ENTROPY_MIN_LENGTH or len(value) > _ENTROPY_MAX_LENGTH:
        return False
    if all(c in "0123456789abcdef" for c in value.lower()):
        # Pure hex — commit SHAs, hashes. Not a secret in code.
        return False
    if "/" in value and value.count("/") > 2:
        # Looks like a URL path fragment.
        return False
    if value.startswith(("http://", "https://", "data:", "file:")):
        return False
    if value.replace(".", "").replace("-", "").replace("_", "").isdigit():
        # Version strings, phone numbers, etc.
        return False
    return True


def _append_hardcoded_secret_hints(result: ScanResult, relative: str, content: str) -> None:
    """Emit SecretHint records for literals pasted into source or config
    (#39). Provider-prefixed patterns fire first; a Shannon-entropy
    fallback catches high-entropy literals that don't match a known
    provider. Both redact the value before it lands in evidence_text.
    """
    seen: set[tuple[str, str, int]] = {
        (hint.kind, hint.file, hint.line or 0) for hint in result.secret_hints
    }
    matched_spans: list[tuple[int, int]] = []  # positions of provider matches

    for pattern, kind in HARDCODED_SECRET_PATTERNS:
        for match in pattern.finditer(content):
            literal = match.group(1)
            # JWT shape needs additional verification — the base-64 header
            # segment must decode to something starting with `{` and
            # containing an "alg" key. Reject anything that just happens
            # to look like the shape.
            if kind == "jwt" and not _is_jwt_shape(literal):
                continue
            line = _line_of(content, match.start())
            key = (kind, relative, line)
            if key in seen:
                continue
            seen.add(key)
            matched_spans.append((match.start(), match.end()))
            display_name = _redact_secret(literal) if kind != "pem_private_key" else literal
            result.secret_hints.append(
                SecretHint(
                    name=display_name,
                    file=relative,
                    line=line,
                    evidence_text=_line_snippet(content, match.start()),
                    confidence=1.0,
                    kind=kind,
                )
            )

    # High-entropy fallback — only if no provider match was already found
    # at this position, to avoid double-emitting the same literal.
    def _overlaps_matched(pos: int) -> bool:
        return any(start <= pos < end for start, end in matched_spans)

    for match in _QUOTED_LITERAL.finditer(content):
        literal = match.group(1)
        pos = match.start(1)
        if _overlaps_matched(pos):
            continue
        if not _looks_like_secret_candidate(literal):
            continue
        if _shannon_entropy(literal) < _ENTROPY_THRESHOLD:
            continue
        line = _line_of(content, pos)
        key = ("high_entropy", relative, line)
        if key in seen:
            continue
        seen.add(key)
        result.secret_hints.append(
            SecretHint(
                name=_redact_secret(literal),
                file=relative,
                line=line,
                evidence_text=_line_snippet(content, pos),
                confidence=0.7,
                kind="high_entropy",
            )
        )


def _is_jwt_shape(literal: str) -> bool:
    """Verify the header segment of a candidate JWT decodes to a JSON
    object with an `alg` field. Cheap and precise enough to keep the
    shape regex from spamming."""
    parts = literal.split(".")
    if len(parts) != 3:
        return False
    header_b64 = parts[0]
    # base64url decode with padding tolerance
    padding = "=" * ((4 - len(header_b64) % 4) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64 + padding)
    except (ValueError, binascii.Error):
        return False
    try:
        header_text = header_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not header_text.startswith("{") or "alg" not in header_text.lower():
        return False
    return True
