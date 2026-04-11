from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points
import logging
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from .models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint
from .scanner import (
    AUTH_KEYWORDS,
    AUTH_PATTERNS,
    CODE_EXTENSIONS,
    DB_KEYWORDS,
    DB_PATTERNS,
    EXTERNAL_CALL_PATTERNS,
    SECRET_PATTERNS,
    extract_routes,
    scan_repo,
)

logger = logging.getLogger(__name__)

ANALYZER_ENTRYPOINT_GROUP = "attackmap.analyzers"

# Backward-compatible structured signal contract used by the lower-level scanner tests.
class AnalyzerSignals(BaseModel):
    routes: list[Route] = Field(default_factory=list)
    external_calls: list[ExternalCall] = Field(default_factory=list)
    databases: list[DatabaseHint] = Field(default_factory=list)
    auth_hints: list[AuthHint] = Field(default_factory=list)
    secret_hints: list[SecretHint] = Field(default_factory=list)


@dataclass(frozen=True)
class AnalyzerContext:
    root_path: Path
    file_path: Path
    relative_path: str
    content: str
    suffix: str
    language: str


class FileAnalyzer(Protocol):
    name: str

    def analyze(self, context: AnalyzerContext) -> AnalyzerSignals: ...


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


FILE_ANALYZERS: tuple[FileAnalyzer, ...] = (
    RouteAnalyzer(),
    ExternalCallAnalyzer(),
    DatabaseAnalyzer(),
    AuthAnalyzer(),
    SecretAnalyzer(),
)


def get_builtin_analyzers() -> tuple[FileAnalyzer, ...]:
    return FILE_ANALYZERS


def merge_analyzer_signals(scan: ScanResult, signals: AnalyzerSignals) -> None:
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


# Repository-level analyzer contract used by the newer analyzer architecture.
AnalyzerResult = ScanResult


@dataclass(frozen=True)
class AnalyzerMetadata:
    name: str
    description: str
    scope: str
    ecosystems: tuple[str, ...]


class Analyzer(Protocol):
    metadata: AnalyzerMetadata

    @property
    def name(self) -> str: ...

    def analyze(self, root: str | Path) -> AnalyzerResult: ...


class DefaultAnalyzer:
    metadata = AnalyzerMetadata(
        name="default",
        description="Fallback built-in analyzer for the remaining scanner-backed ecosystems.",
        scope="Fallback scanner coverage for supported TypeScript code paths not yet handled by a specialized analyzer.",
        ecosystems=("typescript",),
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return scan_repo(root, suffixes=set(CODE_EXTENSIONS) - {".py", ".js"})


class BuiltinPythonWebAnalyzer:
    metadata = AnalyzerMetadata(
        name="python-web",
        description="Built-in analyzer for Python web frameworks and related security signals.",
        scope="Python source files handled by the current scanner-backed web heuristics.",
        ecosystems=("python", "fastapi", "flask"),
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return scan_repo(root, suffixes={".py"})


class BuiltinJavaScriptWebAnalyzer:
    metadata = AnalyzerMetadata(
        name="javascript-web",
        description="Built-in analyzer for JavaScript web frameworks and related security signals.",
        scope="JavaScript source files handled by the current scanner-backed web heuristics.",
        ecosystems=("javascript", "express", "node"),
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return scan_repo(root, suffixes={".js"})


def get_builtin_repository_analyzers() -> list[Analyzer]:
    return [BuiltinPythonWebAnalyzer(), BuiltinJavaScriptWebAnalyzer(), DefaultAnalyzer()]


def discover_installed_analyzers(group: str = ANALYZER_ENTRYPOINT_GROUP) -> list[Analyzer]:
    discovered: list[Analyzer] = []
    all_entry_points = entry_points()
    if hasattr(all_entry_points, "select"):
        candidates = list(all_entry_points.select(group=group))
    else:
        candidates = list(all_entry_points.get(group, ()))

    for analyzer_entry_point in sorted(candidates, key=lambda candidate: candidate.name):
        analyzer = _load_discovered_analyzer(analyzer_entry_point)
        if analyzer is None:
            continue
        discovered.append(analyzer)
    return discovered


def _load_discovered_analyzer(analyzer_entry_point: object) -> Analyzer | None:
    entry_name = getattr(analyzer_entry_point, "name", "<unknown>")
    try:
        loaded_object = analyzer_entry_point.load()
    except Exception as exc:
        logger.warning("Failed to load analyzer entry point '%s': %s", entry_name, exc)
        return None

    try:
        analyzer = _coerce_analyzer_instance(loaded_object)
    except Exception as exc:
        logger.warning("Failed to initialize analyzer entry point '%s': %s", entry_name, exc)
        return None

    if not _is_valid_analyzer(analyzer):
        logger.warning("Skipping entry point '%s': loaded object is not a valid analyzer.", entry_name)
        return None
    return analyzer


def _coerce_analyzer_instance(loaded_object: object) -> object:
    if isinstance(loaded_object, type):
        return loaded_object()
    if hasattr(loaded_object, "analyze") and hasattr(loaded_object, "metadata"):
        return loaded_object
    if callable(loaded_object):
        return loaded_object()
    return loaded_object


def _is_valid_analyzer(candidate: object) -> bool:
    if not hasattr(candidate, "metadata") or not hasattr(candidate, "analyze") or not callable(candidate.analyze):
        return False

    candidate_name = getattr(candidate, "name", None)
    if not isinstance(candidate_name, str) or not candidate_name.strip():
        return False

    metadata = getattr(candidate, "metadata")
    metadata_name = getattr(metadata, "name", None)
    return isinstance(metadata_name, str) and bool(metadata_name.strip())


def get_registered_analyzers() -> list[Analyzer]:
    analyzers = [*get_builtin_repository_analyzers(), *discover_installed_analyzers()]
    deduplicated: list[Analyzer] = []
    seen_names: set[str] = set()

    for analyzer in analyzers:
        if analyzer.name in seen_names:
            logger.warning("Skipping duplicate analyzer name '%s'.", analyzer.name)
            continue
        seen_names.add(analyzer.name)
        deduplicated.append(analyzer)

    return deduplicated


def get_analyzer_metadata(analyzer: Analyzer) -> AnalyzerMetadata:
    return analyzer.metadata


def analyze_repository(root: str | Path, analyzers: Iterable[Analyzer] | None = None) -> AnalyzerResult:
    repo_root = Path(root).resolve()
    active_analyzers = list(analyzers) if analyzers is not None else get_registered_analyzers()
    results = [analyzer.analyze(repo_root) for analyzer in active_analyzers]
    if not results:
        return AnalyzerResult(root=str(repo_root))
    return merge_analyzer_results(results, root=repo_root)


def merge_analyzer_results(
    results: Iterable[AnalyzerResult],
    root: str | Path | None = None,
) -> AnalyzerResult:
    result_list = list(results)
    if not result_list:
        resolved_root = Path(root).resolve() if root is not None else Path(".").resolve()
        return AnalyzerResult(root=str(resolved_root))

    resolved_root = Path(root).resolve() if root is not None else Path(result_list[0].root).resolve()
    merged = AnalyzerResult(root=str(resolved_root))
    route_keys: set[tuple[str, str, str]] = set()
    external_keys: set[tuple[str, str]] = set()
    database_keys: set[tuple[str, str]] = set()
    auth_keys: set[tuple[str, str]] = set()
    secret_keys: set[tuple[str, str]] = set()

    for result in result_list:
        merged.files_scanned += result.files_scanned
        for language in result.languages:
            if language not in merged.languages:
                merged.languages.append(language)
        _merge_unique_items(merged.routes, route_keys, result.routes, lambda item: (item.path, item.method, item.file))
        _merge_unique_items(merged.external_calls, external_keys, result.external_calls, lambda item: (item.target, item.file))
        _merge_unique_items(merged.databases, database_keys, result.databases, lambda item: (item.kind, item.file))
        _merge_unique_items(merged.auth_hints, auth_keys, result.auth_hints, lambda item: (item.hint, item.file))
        _merge_unique_items(merged.secret_hints, secret_keys, result.secret_hints, lambda item: (item.name, item.file))

    merged.languages.sort()
    return merged


def _merge_unique_items[T, K](
    destination: list[T],
    seen: set[K],
    items: Iterable[T],
    key_fn: Callable[[T], K],
) -> None:
    for item in items:
        key = key_fn(item)
        if key in seen:
            continue
        seen.add(key)
        destination.append(item)
