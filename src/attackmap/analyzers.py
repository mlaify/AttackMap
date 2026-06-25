from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points
import json
import logging
from pathlib import Path
import subprocess
import sys
from typing import Protocol, TypeVar

_T = TypeVar("_T")
_K = TypeVar("_K")
from urllib.error import URLError
from urllib.request import urlopen

from pydantic import BaseModel, Field

from .sdk.contracts import (
    AnalyzerMetadata,
    AnalyzerProtocol,
    AnalyzerRepositoryModule,
    AnalyzerResult,
    normalize_analyzer_metadata,
)
from .sdk.models import (
    AuthHint,
    DatabaseHint,
    EdgeHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)
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
ANALYZER_ORG_PREFIX = "mlaify/"
ANALYZER_ORG_BASE_URL = "https://github.com/mlaify"
ANALYZER_ORG_API_URL = "https://api.github.com/orgs/mlaify/repos?per_page=100&type=public"

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


# Backward-compatible alias for existing imports from attackmap.analyzers.
Analyzer = AnalyzerProtocol


class DefaultAnalyzer:
    metadata = AnalyzerMetadata(
        name="default",
        display_name="Default Analyzer",
        version="0.1.0",
        description="Fallback built-in analyzer for the remaining scanner-backed ecosystems.",
        scope="Fallback scanner coverage for supported TypeScript code paths not yet handled by a specialized analyzer.",
        targets=[],
        languages=["typescript"],
        priority=100,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return scan_repo(root, suffixes=set(CODE_EXTENSIONS) - {".py", ".js"})


class BuiltinPythonWebAnalyzer:
    metadata = AnalyzerMetadata(
        name="python-web",
        display_name="Python Web Analyzer",
        version="0.1.0",
        description="Built-in analyzer for Python web frameworks and related security signals.",
        scope="Python source files handled by the current scanner-backed web heuristics.",
        targets=["fastapi", "flask"],
        languages=["python"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return scan_repo(root, suffixes={".py"})


class BuiltinJavaScriptWebAnalyzer:
    metadata = AnalyzerMetadata(
        name="javascript-web",
        display_name="JavaScript Web Analyzer",
        version="0.1.0",
        description="Built-in analyzer for JavaScript web frameworks and related security signals.",
        scope="JavaScript source files handled by the current scanner-backed web heuristics.",
        targets=["express", "node"],
        languages=["javascript"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
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

    try:
        canonical_metadata = normalize_analyzer_metadata(getattr(analyzer, "metadata", None))
    except Exception as exc:
        logger.warning("Failed to normalize analyzer metadata for '%s': %s", entry_name, exc)
        return None
    try:
        setattr(analyzer, "metadata", canonical_metadata)
    except Exception:
        # Some analyzers may expose read-only metadata attributes; normalization is still validated.
        pass

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

    try:
        metadata = normalize_analyzer_metadata(getattr(candidate, "metadata"))
    except Exception:
        return False
    return isinstance(metadata.name, str) and bool(metadata.name.strip())


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


def select_requested_analyzers(
    requested_modules: Iterable[str],
    *,
    auto_install: bool = False,
    installer: Callable[[str], None] | None = None,
) -> list[Analyzer]:
    requested_names = [_normalize_analyzer_name(module) for module in requested_modules if module.strip()]
    if not requested_names:
        return []

    resolved = _match_requested_analyzers(requested_names)
    missing_names = [name for name in requested_names if name not in resolved]

    if missing_names and auto_install:
        install_fn = installer if installer is not None else install_analyzer_module
        for missing_name in missing_names:
            try:
                install_fn(_derive_repo_name(missing_name))
            except Exception as exc:
                raise ValueError(f"Failed to install analyzer module '{missing_name}': {exc}") from exc
        resolved = _match_requested_analyzers(requested_names)
        missing_names = [name for name in requested_names if name not in resolved]

    if missing_names:
        missing_text = ", ".join(missing_names)
        raise ValueError(f"Requested analyzer module(s) not available: {missing_text}")

    selected: list[Analyzer] = []
    seen: set[str] = set()
    for name in requested_names:
        if name in seen:
            continue
        seen.add(name)
        selected.append(resolved[name])
    return selected


def install_analyzer_module(repo_name: str) -> None:
    normalized_repo = _normalize_repo_name(repo_name)
    module_url = f"git+{ANALYZER_ORG_BASE_URL}/{normalized_repo}.git"
    logger.info("Installing analyzer module from %s", module_url)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", module_url],
        check=True,
        capture_output=True,
        text=True,
    )


def _match_requested_analyzers(requested_names: Iterable[str]) -> dict[str, Analyzer]:
    available = {analyzer.name: analyzer for analyzer in get_registered_analyzers()}
    return {name: available[name] for name in requested_names if name in available}


def _normalize_analyzer_name(module: str) -> str:
    normalized = module.strip().lower().removesuffix(".git")
    if normalized.startswith(ANALYZER_ORG_PREFIX):
        normalized = normalized[len(ANALYZER_ORG_PREFIX) :]
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("attackmap-analyzer-"):
        normalized = normalized.removeprefix("attackmap-analyzer-")
    return normalized


def _normalize_repo_name(repo_name: str) -> str:
    normalized = repo_name.strip().lower().removesuffix(".git")
    if normalized.startswith(ANALYZER_ORG_PREFIX):
        normalized = normalized[len(ANALYZER_ORG_PREFIX) :]
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("attackmap-analyzer-"):
        return normalized
    return f"attackmap-analyzer-{normalized}"


def _derive_repo_name(analyzer_name: str) -> str:
    return _normalize_repo_name(analyzer_name)


def get_analyzer_metadata(analyzer: Analyzer) -> AnalyzerMetadata:
    return normalize_analyzer_metadata(analyzer.metadata)


def get_available_modules() -> list[AnalyzerMetadata]:
    return [get_analyzer_metadata(analyzer) for analyzer in get_registered_analyzers()]


def get_available_repository_modules(
    *,
    fetcher: Callable[[str], list[dict[str, object]]] | None = None,
) -> list[AnalyzerRepositoryModule]:
    fetch_fn = fetcher if fetcher is not None else _fetch_org_repositories
    projects = fetch_fn(ANALYZER_ORG_API_URL)
    modules: list[AnalyzerRepositoryModule] = []
    for project in projects:
        repo_name = str(project.get("name", "")).strip()
        if not repo_name.startswith("attackmap-analyzer-"):
            continue
        analyzer_name = _normalize_analyzer_name(repo_name)
        web_url = str(project.get("html_url", f"{ANALYZER_ORG_BASE_URL}/{repo_name}")).strip()
        modules.append(
            AnalyzerRepositoryModule(
                analyzer_name=analyzer_name,
                repo_name=repo_name,
                web_url=web_url,
            )
        )
    modules.sort(key=lambda module: module.analyzer_name)
    return modules


def _fetch_org_repositories(api_url: str) -> list[dict[str, object]]:
    try:
        with urlopen(api_url, timeout=10) as response:
            payload = response.read().decode("utf-8")
    except URLError as exc:
        raise ValueError(f"Unable to reach analyzer module registry: {exc}") from exc
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid analyzer module registry response: {exc}") from exc
    if not isinstance(decoded, list):
        raise ValueError("Unexpected analyzer module registry response shape.")
    return [item for item in decoded if isinstance(item, dict)]


def analyze_repository(root: str | Path, analyzers: Iterable[Analyzer] | None = None) -> AnalyzerResult:
    repo_root = Path(root).resolve()
    active_analyzers = resolve_run_analyzers(repo_root, analyzers=analyzers)
    results = [analyzer.analyze(repo_root) for analyzer in active_analyzers]
    if not results:
        return AnalyzerResult(root=str(repo_root))
    return merge_analyzer_results(results, root=repo_root)


def resolve_run_analyzers(root: str | Path, analyzers: Iterable[Analyzer] | None = None) -> list[Analyzer]:
    repo_root = Path(root).resolve()
    registered = list(analyzers) if analyzers is not None else get_registered_analyzers()
    return [analyzer for analyzer in registered if _should_run_analyzer(analyzer, repo_root)]


def _should_run_analyzer(analyzer: Analyzer, repo_root: Path) -> bool:
    detect_fn = getattr(analyzer, "detect", None)
    if detect_fn is None:
        return True
    if not callable(detect_fn):
        return True
    try:
        return bool(detect_fn(repo_root))
    except Exception as exc:
        logger.warning("Analyzer '%s' detect() failed: %s", analyzer.name, exc)
        return False


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
    service_keys: set[tuple[str, str]] = set()
    edge_keys: set[tuple[str, str]] = set()
    entrypoint_keys: set[tuple[str, str]] = set()
    protocol_keys: set[tuple[str, str]] = set()
    framework_keys: set[tuple[str, str]] = set()
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
        _merge_unique_items(merged.service_hints, service_keys, result.service_hints, lambda item: (item.hint, item.file))
        _merge_unique_items(merged.edge_hints, edge_keys, result.edge_hints, lambda item: (item.hint, item.file))
        _merge_unique_items(
            merged.entrypoint_hints, entrypoint_keys, result.entrypoint_hints, lambda item: (item.hint, item.file)
        )
        _merge_unique_items(merged.protocol_hints, protocol_keys, result.protocol_hints, lambda item: (item.hint, item.file))
        _merge_unique_items(
            merged.framework_hints, framework_keys, result.framework_hints, lambda item: (item.hint, item.file)
        )
        _merge_unique_items(merged.secret_hints, secret_keys, result.secret_hints, lambda item: (item.name, item.file))

    merged.languages.sort()
    return merged


def _merge_unique_items(
    destination: list[_T],
    seen: set[_K],
    items: Iterable[_T],
    key_fn: Callable[[_T], _K],
) -> None:
    for item in items:
        key = key_fn(item)
        if key in seen:
            continue
        seen.add(key)
        destination.append(item)
