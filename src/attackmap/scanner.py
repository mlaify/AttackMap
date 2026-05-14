from __future__ import annotations

import re
from pathlib import Path

from .sdk.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

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
    r"\b(\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)['\"]",
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
METHOD_LIST_PATTERN = re.compile(r"['\"](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)['\"]", re.IGNORECASE)

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
    (re.compile(r"create_engine\(\s*['\"](?:postgresql|mysql|sqlite|mssql|oracle)\+?", re.IGNORECASE), "sql"),
    (re.compile(r"sqlite3\.connect\(", re.IGNORECASE), "sqlite"),
    (re.compile(r"psycopg(?:2)?\.connect\(", re.IGNORECASE), "postgresql"),
    (re.compile(r"(?:AsyncIOMotorClient|MongoClient)\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"redis\.(?:Redis|StrictRedis)\(", re.IGNORECASE), "redis"),
    (re.compile(r"new\s+PrismaClient\(", re.IGNORECASE), "sql"),
    (re.compile(r"mongoose\.connect\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"new\s+Pool\(", re.IGNORECASE), "postgresql"),
]

AUTH_KEYWORDS = [
    "jwt",
    "oauth",
    "auth0",
    "apikey",
    "api_key",
    "bearer",
    "session",
    "password",
    "token",
    "mfa",
]

AUTH_PATTERNS = [
    (re.compile(r"@login_required\b", re.IGNORECASE), "login_required"),
    (re.compile(r"@jwt_required\b", re.IGNORECASE), "jwt"),
    (re.compile(r"Depends\(\s*(?:oauth2_scheme|get_current_user|current_user|verify_token)\s*\)", re.IGNORECASE), "depends_auth"),
    (re.compile(r"OAuth2PasswordBearer\(", re.IGNORECASE), "oauth"),
    (re.compile(r"request\.authorization\b", re.IGNORECASE), "authorization"),
    (re.compile(r"Authorization['\"]?\s*\]", re.IGNORECASE), "authorization"),
    (re.compile(r"passport\.authenticate\(", re.IGNORECASE), "passport"),
    (re.compile(r"\b(?:verify|require)Token\b", re.IGNORECASE), "token"),
    (re.compile(r"\bauthMiddleware\b", re.IGNORECASE), "auth_middleware"),
]

SECRET_PATTERNS = [
    re.compile(r"os\.getenv\(['\"]([^'\"]*(SECRET|TOKEN|KEY|PASSWORD)[^'\"]*)['\"]", re.IGNORECASE),
    re.compile(r"process\.env\.([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*)", re.IGNORECASE),
]


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


def _join_route_parts(prefix: str, path: str) -> str:
    base = prefix.strip()
    suffix = path.strip()

    if not base:
        return suffix or "/"
    if not suffix:
        return base or "/"
    if base == "/":
        return suffix if suffix.startswith("/") else f"/{suffix}"
    if suffix == "/":
        return base
    return f"{base.rstrip('/')}/{suffix.lstrip('/')}"


def _extract_methods(args: str, default_method: str = "ANY") -> list[str]:
    methods = [match.upper() for match in METHOD_LIST_PATTERN.findall(args)]
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
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        routes.append(
            Route(
                path=full_path,
                method=method.upper(),
                file=file,
                line=_line_of(content, match.start()),
            )
        )

    for match in EXPRESS_CHAIN_ROUTE_PATTERN.finditer(content):
        router_name, route_path, chain = match.group(1), match.group(2), match.group("chain")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        chain_offset = match.start("chain")
        for method_match in re.finditer(r"\.(get|post|put|delete|patch|options|head)\s*\(", chain, re.IGNORECASE):
            routes.append(
                Route(
                    path=full_path,
                    method=method_match.group(1).upper(),
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


def scan_repo(root: str | Path, suffixes: set[str] | None = None) -> ScanResult:
    root_path = Path(root).resolve()
    result = ScanResult(root=str(root_path))

    for file_path in root_path.rglob("*"):
        if not file_path.is_file() or not should_scan_with_suffixes(file_path, suffixes):
            continue

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
                    )
                )

    result.languages.sort()
    return result
