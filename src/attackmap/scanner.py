from __future__ import annotations

import re
from pathlib import Path

from .models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

CODE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

ROUTE_PATTERNS = [
    re.compile(r"@app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\)", re.IGNORECASE),
    re.compile(r"@router\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\)", re.IGNORECASE),
    re.compile(r"app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"router\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]", re.IGNORECASE),
]

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

SECRET_PATTERNS = [
    re.compile(r"os\.getenv\(['\"]([^'\"]*(SECRET|TOKEN|KEY|PASSWORD)[^'\"]*)['\"]", re.IGNORECASE),
    re.compile(r"process\.env\.([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*)", re.IGNORECASE),
]


def should_scan(path: Path) -> bool:
    if path.name.startswith("."):
        return False
    if any(part in {"node_modules", ".git", ".venv", "dist", "build"} for part in path.parts):
        return False
    return path.suffix in CODE_EXTENSIONS


def scan_repo(root: str | Path) -> ScanResult:
    root_path = Path(root).resolve()
    result = ScanResult(root=str(root_path))

    for file_path in root_path.rglob("*"):
        if not file_path.is_file() or not should_scan(file_path):
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

        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                method, route_path = match.groups()
                result.routes.append(Route(path=route_path, method=method.upper(), file=relative))

        for pattern in EXTERNAL_CALL_PATTERNS:
            for match in pattern.finditer(content):
                target = match.groups()[-1]
                result.external_calls.append(ExternalCall(target=target, file=relative))

        lowered = content.lower()
        for keyword, kind in DB_KEYWORDS.items():
            if keyword in lowered:
                result.databases.append(DatabaseHint(kind=kind, file=relative))

        for keyword in AUTH_KEYWORDS:
            if keyword in lowered:
                result.auth_hints.append(AuthHint(hint=keyword, file=relative))

        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                secret_name = match.groups()[0]
                result.secret_hints.append(SecretHint(name=secret_name, file=relative))

    result.languages.sort()
    return result
