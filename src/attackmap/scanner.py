from __future__ import annotations

from pathlib import Path

from .analyzers import AnalyzerContext, get_builtin_analyzers, merge_analyzer_signals
from .models import ScanResult

CODE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


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
            )
        )

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


def _append_unique_database_hints(result: ScanResult, relative: str, content: str, lowered: str) -> None:
    seen = {(hint.kind, hint.file) for hint in result.databases}

    for pattern, kind in DB_PATTERNS:
        if pattern.search(content) and (kind, relative) not in seen:
            result.databases.append(DatabaseHint(kind=kind, file=relative))
            seen.add((kind, relative))

    for keyword, kind in DB_KEYWORDS.items():
        if keyword in lowered and (kind, relative) not in seen:
            result.databases.append(DatabaseHint(kind=kind, file=relative))
            seen.add((kind, relative))


def _append_unique_auth_hints(result: ScanResult, relative: str, content: str, lowered: str) -> None:
    seen = {(hint.hint, hint.file) for hint in result.auth_hints}

    for pattern, hint in AUTH_PATTERNS:
        if pattern.search(content) and (hint, relative) not in seen:
            result.auth_hints.append(AuthHint(hint=hint, file=relative))
            seen.add((hint, relative))

    for keyword in AUTH_KEYWORDS:
        if keyword in lowered and (keyword, relative) not in seen:
            result.auth_hints.append(AuthHint(hint=keyword, file=relative))
            seen.add((keyword, relative))


def scan_repo(root: str | Path, suffixes: set[str] | None = None) -> ScanResult:
    root_path = Path(root).resolve()
    result = ScanResult(root=str(root_path))
    analyzers = get_builtin_analyzers()

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

        context = AnalyzerContext(
            root_path=root_path,
            file_path=file_path,
            relative_path=str(file_path.relative_to(root_path)),
            content=content,
            suffix=file_path.suffix,
            language=language,
        )

        for analyzer in analyzers:
            merge_analyzer_signals(result, analyzer.analyze(context))

    result.languages.sort()
    return result
