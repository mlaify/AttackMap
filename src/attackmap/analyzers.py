from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from .models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

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


class AnalyzerSignals(BaseModel):
    """Structured extraction output emitted by analyzers before core reasoning."""
    routes: list[Route] = Field(default_factory=list)
    external_calls: list[ExternalCall] = Field(default_factory=list)
    databases: list[DatabaseHint] = Field(default_factory=list)
    auth_hints: list[AuthHint] = Field(default_factory=list)
    secret_hints: list[SecretHint] = Field(default_factory=list)


@dataclass(frozen=True)
class AnalyzerContext:
    """Stable file-level context passed from core scanning to analyzers."""
    root_path: Path
    file_path: Path
    relative_path: str
    content: str
    suffix: str
    language: str


class Analyzer(Protocol):
    """Narrow analyzer interface used by built-in and future external analyzers."""
    name: str

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals: ...


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
        routes.append(Route(path=_join_route_parts(prefixes.get(router_name, ""), route_path), method=method.upper(), file=file))

    for match in FASTAPI_API_ROUTE_PATTERN.finditer(content):
        router_name, route_path, args = match.group(1), match.group(2), match.group("args")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        for method in _extract_methods(args, default_method="ANY"):
            routes.append(Route(path=full_path, method=method, file=file))

    for match in FLASK_ROUTE_PATTERN.finditer(content):
        router_name, route_path, args = match.group(1), match.group(2), match.group("args")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        for method in _extract_methods(args, default_method="GET"):
            routes.append(Route(path=full_path, method=method, file=file))

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
        routes.append(Route(path=full_path, method=method.upper(), file=file))

    for match in EXPRESS_CHAIN_ROUTE_PATTERN.finditer(content):
        router_name, route_path, chain = match.group(1), match.group(2), match.group("chain")
        full_path = _join_route_parts(prefixes.get(router_name, ""), route_path)
        for method_match in re.finditer(r"\.(get|post|put|delete|patch|options|head)\s*\(", chain, re.IGNORECASE):
            routes.append(Route(path=full_path, method=method_match.group(1).upper(), file=file))

    return routes


def extract_routes(content: str, file: str, suffix: str) -> list[Route]:
    if suffix == ".py":
        return _extract_python_routes(content, file)
    if suffix in {".js", ".ts", ".tsx"}:
        return _extract_javascript_routes(content, file)
    return []


class RouteAnalyzer:
    name = "routes"

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals:
        return AnalyzerSignals(routes=extract_routes(context.content, context.relative_path, context.suffix))


class ExternalCallAnalyzer:
    name = "external_calls"

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals:
        calls: list[ExternalCall] = []
        for pattern in EXTERNAL_CALL_PATTERNS:
            for match in pattern.finditer(context.content):
                calls.append(ExternalCall(target=match.groups()[-1], file=context.relative_path))
        return AnalyzerSignals(external_calls=calls)


class DatabaseAnalyzer:
    name = "databases"

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals:
        lowered = context.content.lower()
        databases: list[DatabaseHint] = []
        seen: set[tuple[str, str]] = set()

        for pattern, kind in DB_PATTERNS:
            if pattern.search(context.content) and (kind, context.relative_path) not in seen:
                databases.append(DatabaseHint(kind=kind, file=context.relative_path))
                seen.add((kind, context.relative_path))

        for keyword, kind in DB_KEYWORDS.items():
            if keyword in lowered and (kind, context.relative_path) not in seen:
                databases.append(DatabaseHint(kind=kind, file=context.relative_path))
                seen.add((kind, context.relative_path))

        return AnalyzerSignals(databases=databases)


class AuthAnalyzer:
    name = "auth"

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals:
        lowered = context.content.lower()
        auth_hints: list[AuthHint] = []
        seen: set[tuple[str, str]] = set()

        for pattern, hint in AUTH_PATTERNS:
            if pattern.search(context.content) and (hint, context.relative_path) not in seen:
                auth_hints.append(AuthHint(hint=hint, file=context.relative_path))
                seen.add((hint, context.relative_path))

        for keyword in AUTH_KEYWORDS:
            if keyword in lowered and (keyword, context.relative_path) not in seen:
                auth_hints.append(AuthHint(hint=keyword, file=context.relative_path))
                seen.add((keyword, context.relative_path))

        return AnalyzerSignals(auth_hints=auth_hints)


class SecretAnalyzer:
    name = "secrets"

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals:
        secret_hints: list[SecretHint] = []
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(context.content):
                secret_hints.append(SecretHint(name=match.groups()[0], file=context.relative_path))
        return AnalyzerSignals(secret_hints=secret_hints)


BUILTIN_ANALYZERS: tuple[Analyzer, ...] = (
    RouteAnalyzer(),
    ExternalCallAnalyzer(),
    DatabaseAnalyzer(),
    AuthAnalyzer(),
    SecretAnalyzer(),
)


def get_builtin_analyzers() -> tuple[Analyzer, ...]:
    return BUILTIN_ANALYZERS


def merge_analyzer_signals(scan: ScanResult, signals: AnalyzerSignals) -> None:
    """
    Core-owned merge rules for analyzer output.

    Routes, external calls, and secret hints are accumulated in analyzer order.
    Databases and auth hints are deduplicated by `(value, file)` to reduce noisy overlap.
    """
    scan.routes.extend(signals.routes)
    scan.external_calls.extend(signals.external_calls)
    scan.secret_hints.extend(signals.secret_hints)

    seen_databases = {(hint.kind, hint.file) for hint in scan.databases}
    for hint in signals.databases:
        key = (hint.kind, hint.file)
        if key not in seen_databases:
            scan.databases.append(hint)
            seen_databases.add(key)

    seen_auth_hints = {(hint.hint, hint.file) for hint in scan.auth_hints}
    for hint in signals.auth_hints:
        key = (hint.hint, hint.file)
        if key not in seen_auth_hints:
            scan.auth_hints.append(hint)
            seen_auth_hints.add(key)
