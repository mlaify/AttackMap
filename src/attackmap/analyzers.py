from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points
import importlib
import inspect
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from .progress import ScanProgress
from urllib.error import URLError
from urllib.request import urlopen

from pydantic import BaseModel, Field

from .srcpaths import JS_TS_SUFFIXES, SKIP_DIRS, in_skipped_dir, is_skipped_dir
from .plugins_lock import OFFICIAL_PLUGINS
from .safe_fs import walk_repo
from .merge import MERGE_SCHEMA, initial_seen, merge_into

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
    _external_call_fields,
    SECRET_PATTERNS,
    extract_routes,
    run_repo_passes,
    scan_files,
    scan_repo,
)

logger = logging.getLogger(__name__)

ANALYZER_ENTRYPOINT_GROUP = "attackmap.analyzers"

# Directories excluded from `detect()` walks in built-in analyzers.
# Mirrors the scanner's own scan-time filter — anything below these
# paths is vendored / generated and shouldn't count toward "this repo
# looks like JS/TS."
_SKIP_DIRS = SKIP_DIRS  # shared set (#215)
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
                target, method = _external_call_fields(match)
                calls.append(
                    ExternalCall(target=target, method=method, file=context.relative_path)
                )
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
    """Apply file-by-file analyzer signals onto a running scan result.

    `AnalyzerSignals` is the narrow per-file shape used by the built-in
    micro-analyzers in this module. Dedup follows :data:`merge.MERGE_SCHEMA`
    for the field families it covers; routes, external calls, and secrets
    have always been straight extend (intentional: per-file analyzers emit
    one batch per file, dedup happens at the result-level merge step).
    """
    scan.routes.extend(signals.routes)
    scan.external_calls.extend(signals.external_calls)
    scan.secret_hints.extend(signals.secret_hints)

    rules = {r.attr: r for r in MERGE_SCHEMA}
    for attr in ("databases", "auth_hints"):
        rule = rules[attr]
        merge_into(scan, getattr(signals, attr), rule, initial_seen(scan, rule))


# Backward-compatible alias for existing imports from attackmap.analyzers.
Analyzer = AnalyzerProtocol


class DefaultAnalyzer:
    """Catch-all for code file suffixes not claimed by a specialized
    built-in analyzer. Currently a no-op since python-web + javascript-web
    together cover every entry in CODE_EXTENSIONS — kept so future
    additions (e.g. `.go`, `.rs`) get picked up automatically until a
    dedicated built-in ships."""

    # Suffixes owned by specialized built-in analyzers. Kept in sync
    # with BuiltinPythonWebAnalyzer + BuiltinJavaScriptWebAnalyzer.
    _CLAIMED_SUFFIXES = {".py"} | JS_TS_SUFFIXES

    metadata = AnalyzerMetadata(
        name="default",
        display_name="Default Analyzer",
        version="0.1.0",
        description="Fallback built-in analyzer for code file suffixes not claimed by a specialized built-in.",
        scope="Any CODE_EXTENSIONS suffix not covered by python-web or javascript-web.",
        targets=[],
        languages=[],
        priority=100,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(
        self, root: str | Path, progress: "ScanProgress | None" = None, recall: bool = False
    ) -> AnalyzerResult:
        return scan_files(
            root,
            suffixes=set(CODE_EXTENSIONS) - self._CLAIMED_SUFFIXES,
            progress=progress,
        )


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

    def analyze(
        self, root: str | Path, progress: "ScanProgress | None" = None, recall: bool = False
    ) -> AnalyzerResult:
        return scan_files(root, suffixes={".py"}, progress=progress)


class BuiltinJavaScriptWebAnalyzer:
    """Broad built-in JavaScript / TypeScript web analyzer.

    Intentionally shallow — this is the *fallback* that any JS/TS repo
    gets even when no plugin is installed. Deep coverage (NestJS, tRPC,
    XRPC, workspaces, BullMQ/Kafka async workers) lives in the
    ``attackmap-analyzer-node-service`` plugin and merges on top via
    the existing merge pipeline. Keeping this analyzer thin means the
    plugin has room to grow without stomping on core.
    """

    _JS_SUFFIXES = set(JS_TS_SUFFIXES)
    _WEB_DEPENDENCY_TOKENS = (
        "express",
        "fastify",
        "koa",
        "hapi",
        "hono",
        "elysia",
        "next",
        "nuxt",
        "nestjs",
        "@nestjs/",
        "@trpc/",
        "@atproto/xrpc-server",
    )

    metadata = AnalyzerMetadata(
        name="javascript-web",
        display_name="JavaScript / TypeScript Web Analyzer",
        version="0.2.0",
        description="Broad built-in analyzer for JavaScript and TypeScript web applications.",
        scope="JavaScript/TypeScript source files (.js/.jsx/.mjs/.cjs/.ts/.tsx). Deep framework coverage lives in attackmap-analyzer-node-service; this is the fallback.",
        targets=["express", "fastify", "koa", "node"],
        languages=["javascript", "typescript"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        """Return True when the repo looks JS/TS-shaped.

        Signals (any one is sufficient):
        - `package.json` at any depth,
        - a JS/TS-family file at any depth (bounded by SKIP_DIRS),
        - `package.json` referencing a known web framework (deeper
          signal — costs one file read).
        """
        repo = Path(root)
        if not repo.exists() or not repo.is_dir():
            return False
        try:
            for candidate in walk_repo(repo, prune=is_skipped_dir):
                if in_skipped_dir(candidate.relative_to(repo)):
                    continue
                if candidate.name == "package.json":
                    return True
                if candidate.suffix in self._JS_SUFFIXES:
                    return True
        except OSError:
            return False
        return False

    def analyze(
        self, root: str | Path, progress: "ScanProgress | None" = None, recall: bool = False
    ) -> AnalyzerResult:
        return scan_files(root, suffixes=self._JS_SUFFIXES, progress=progress)


class BuiltinConfigAnalyzer:
    """Built-in analyzer that walks YAML / TOML / JSON / INI / .env
    config files and extracts DB URLs, service endpoints, and
    secret-shaped literals (see #43).

    Deep parsing lives elsewhere (docker-compose service graph in the
    forthcoming attackmap-analyzer-iac plugin, per #40); this analyzer
    covers the broad-strokes application-config case using the same
    regex-based approach the source scanner uses.
    """

    metadata = AnalyzerMetadata(
        name="config",
        display_name="Config File Analyzer",
        version="0.1.0",
        description="Broad built-in analyzer for YAML / TOML / JSON / INI / .env application config files.",
        scope="Application config files. Extracts DB connection strings, external service URLs, and secret-shaped literals; deep IaC parsing (docker-compose service graph, Dockerfile hardening) lives in attackmap-analyzer-iac.",
        targets=["yaml", "toml", "json", "ini", "env"],
        languages=[],
        priority=30,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        from .config_scanner import should_scan_config_file
        repo = Path(root)
        if not repo.exists() or not repo.is_dir():
            return False
        try:
            for candidate in walk_repo(repo, prune=is_skipped_dir):
                if in_skipped_dir(candidate.relative_to(repo)):
                    continue
                if should_scan_config_file(candidate):
                    return True
        except OSError:
            return False
        return False

    def analyze(self, root: str | Path) -> AnalyzerResult:
        from .config_scanner import scan_config_repo
        return scan_config_repo(root)


def get_builtin_repository_analyzers() -> list[Analyzer]:
    return [
        BuiltinPythonWebAnalyzer(),
        BuiltinJavaScriptWebAnalyzer(),
        BuiltinConfigAnalyzer(),
        DefaultAnalyzer(),
    ]


# Official plugins by package name, pinned to immutable commits (#237).
_OFFICIAL_BY_PACKAGE = {entry["package"]: entry for entry in OFFICIAL_PLUGINS}
TRUSTED_ONLY_ENV = "ATTACKMAP_TRUSTED_ANALYZERS_ONLY"
ALLOW_SYSTEM_INSTALL_ENV = "ATTACKMAP_ALLOW_SYSTEM_INSTALL"


class MissingAnalyzersError(ValueError):
    """Requested official analyzers aren't installed (and weren't auto-installed)."""

    def __init__(self, missing: list[str]) -> None:
        self.missing = missing
        super().__init__(f"Requested analyzer module(s) not available: {', '.join(missing)}")


def official_plugin(name: str) -> dict | None:
    """The lock entry for an official analyzer (by analyzer, package or repo name)."""
    return _OFFICIAL_BY_PACKAGE.get(_normalize_repo_name(name))


def trusted_analyzers_only() -> bool:
    return os.environ.get(TRUSTED_ONLY_ENV, "").strip().lower() in {"1", "true", "yes"}


def _entry_point_distribution(analyzer_entry_point: object) -> str | None:
    dist = getattr(analyzer_entry_point, "dist", None)
    name = getattr(dist, "name", None) if dist is not None else None
    return name.lower().replace("_", "-") if isinstance(name, str) else None


def discover_installed_analyzers(group: str = ANALYZER_ENTRYPOINT_GROUP) -> list[Analyzer]:
    discovered: list[Analyzer] = []
    all_entry_points = entry_points()
    if hasattr(all_entry_points, "select"):
        candidates = list(all_entry_points.select(group=group))
    else:
        candidates = list(all_entry_points.get(group, ()))

    trusted_only = trusted_analyzers_only()
    for analyzer_entry_point in sorted(candidates, key=lambda candidate: candidate.name):
        # Any installed distribution can register an analyzer and run inside
        # every scan (#237): flag ones that aren't official plugins, and skip
        # them entirely in trusted-only mode (the GitHub Action's default).
        distribution = _entry_point_distribution(analyzer_entry_point)
        if distribution not in _OFFICIAL_BY_PACKAGE:
            entry_name = getattr(analyzer_entry_point, "name", "<unknown>")
            if trusted_only:
                logger.warning(
                    "Skipping analyzer '%s' from '%s': not an official AttackMap plugin "
                    "(trusted-analyzers-only).", entry_name, distribution or "unknown distribution"
                )
                continue
            logger.warning(
                "Loading third-party analyzer '%s' from '%s' (not an official AttackMap plugin).",
                entry_name, distribution or "unknown distribution",
            )
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

    # Only official, lock-pinned plugins can ever be installed by name (#237):
    # an unknown or mistyped name is an error, never a network install.
    unofficial = [name for name in missing_names if official_plugin(name) is None]
    if unofficial:
        raise ValueError(
            f"{', '.join(unofficial)}: not an official AttackMap analyzer and not installed. "
            "If you trust a third-party analyzer, install it yourself (pip install <package>)."
        )

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
        raise MissingAnalyzersError(missing_names)

    selected: list[Analyzer] = []
    seen: set[str] = set()
    for name in requested_names:
        if name in seen:
            continue
        seen.add(name)
        selected.append(resolved[name])
    return selected


def analyzer_install_url(repo_name: str) -> str:
    """The pip-installable URL of an official analyzer, pinned to the locked
    commit (#237) — never a moving branch. Unknown names raise ValueError."""
    entry = official_plugin(repo_name)
    if entry is None:
        raise ValueError(f"'{repo_name}' is not an official AttackMap analyzer")
    return f"{entry['package']} @ git+{ANALYZER_ORG_BASE_URL}/{entry['repo']}.git@{entry['git_sha']}"


def analyzer_install_command(repo_name: str) -> list[str]:
    return [sys.executable, "-m", "pip", "install", analyzer_install_url(repo_name)]


def install_analyzer_module(repo_name: str) -> None:
    """pip-install one official analyzer at its pinned commit.

    Refuses to install into a system (non-virtualenv) interpreter unless
    ATTACKMAP_ALLOW_SYSTEM_INSTALL=1, and surfaces pip's own error output.
    """
    command = analyzer_install_command(repo_name)
    in_venv = sys.prefix != sys.base_prefix
    if not in_venv and os.environ.get(ALLOW_SYSTEM_INSTALL_ENV) != "1":
        raise RuntimeError(
            "refusing to pip-install into the system Python interpreter; use a virtualenv/pipx "
            f"install of attackmap, or set {ALLOW_SYSTEM_INSTALL_ENV}=1"
        )
    logger.info("Installing analyzer module: %s", " ".join(command))
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        tail = "\n".join(((exc.stderr or "") + (exc.stdout or "")).strip().splitlines()[-15:])
        raise RuntimeError(f"pip install failed ({' '.join(command[3:])}):\n{tail}") from exc
    importlib.invalidate_caches()


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


def analyze_repository(
    root: str | Path,
    analyzers: Iterable[Analyzer] | None = None,
    progress: "ScanProgress | None" = None,
    recall: bool = False,
) -> AnalyzerResult:
    repo_root = Path(root).resolve()
    active_analyzers = resolve_run_analyzers(repo_root, analyzers=analyzers)
    results: list[AnalyzerResult] = []
    for analyzer in active_analyzers:
        result = _call_analyze(analyzer, repo_root, progress, recall)
        _stamp_provenance(result, analyzer.name)
        results.append(result)
    merged = merge_analyzer_results(results, root=repo_root) if results else AnalyzerResult(root=str(repo_root))
    # Whole-repo passes run once, over every analyzer's merged signals (#219).
    run_repo_passes(merged, repo_root, progress=progress, recall=recall)
    if progress is not None:
        progress.done()
    return merged


def _call_analyze(
    analyzer: Analyzer,
    root: Path,
    progress: "ScanProgress | None",
    recall: bool = False,
) -> AnalyzerResult:
    """Invoke ``analyzer.analyze``, forwarding ``progress``/``recall`` only to
    analyzers that accept them. Keeps the plugin ``analyze(root)`` contract
    intact — old plugins that don't know about these kwargs are called
    unchanged, and ``recall`` is only ever passed when it's on."""
    kwargs: dict[str, object] = {}
    try:
        params = inspect.signature(analyzer.analyze).parameters
        if progress is not None and "progress" in params:
            kwargs["progress"] = progress
        if recall and "recall" in params:
            kwargs["recall"] = recall
    except (TypeError, ValueError):
        pass
    return analyzer.analyze(root, **kwargs)  # type: ignore[call-arg]


def _stamp_provenance(result: AnalyzerResult, analyzer_name: str) -> None:
    """Tag every signal in `result` with the analyzer that produced it.

    Done in core rather than in each analyzer so the 13 published plugins
    don't need to know about the field — they emit signals as they always
    have, and core stamps provenance on the way to the merge. Only stamps
    signals that don't already carry a source (plugins that want to attribute
    a signal to something more specific can pre-populate the field).
    """
    for rule in MERGE_SCHEMA:
        for item in getattr(result, rule.attr):
            if item.source_analyzer is None:
                item.source_analyzer = analyzer_name


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
    """Combine multiple whole-repo analyzer results into one.

    Field-by-field merge behavior is declared in :data:`merge.MERGE_SCHEMA`
    and applied uniformly here. See `merge.py` for the rules.
    """
    result_list = list(results)
    if not result_list:
        resolved_root = Path(root).resolve() if root is not None else Path(".").resolve()
        return AnalyzerResult(root=str(resolved_root))

    resolved_root = Path(root).resolve() if root is not None else Path(result_list[0].root).resolve()
    merged = AnalyzerResult(root=str(resolved_root))
    seen_by_attr: dict[str, set] = {rule.attr: set() for rule in MERGE_SCHEMA}

    for result in result_list:
        merged.files_scanned += result.files_scanned
        for language in result.languages:
            if language not in merged.languages:
                merged.languages.append(language)
        for limitation in result.limitations:
            if limitation not in merged.limitations:
                merged.limitations.append(limitation)
        for rule in MERGE_SCHEMA:
            merge_into(merged, getattr(result, rule.attr), rule, seen_by_attr[rule.attr])

    merged.languages.sort()
    return merged
