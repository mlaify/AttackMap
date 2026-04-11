from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .models import ScanResult
from .scanner import CODE_EXTENSIONS, scan_repo

# For the first migration step, analyzers emit the existing ScanResult shape.
# This keeps the core pipeline stable while creating a clear contract for future
# external analyzers published under the matthewd.xyzAI/attackmap-analyzers subgroup.
AnalyzerResult = ScanResult


@dataclass(frozen=True)
class AnalyzerMetadata:
    """Minimal metadata that describes an analyzer's purpose and scope."""

    name: str
    description: str
    scope: str
    ecosystems: tuple[str, ...]


class Analyzer(Protocol):
    """Lightweight contract for built-in and future external analyzers.

    Core owns graphing, findings, attack paths, and reporting.
    Analyzers only inspect the repository and return structured data.
    """

    metadata: AnalyzerMetadata

    @property
    def name(self) -> str: ...

    def analyze(self, root: str | Path) -> AnalyzerResult: ...


class DefaultAnalyzer:
    """Fallback built-in analyzer for supported code not owned by specialized analyzers."""

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
    """Built-in analyzer for Python web repositories and signals."""

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
    """Built-in analyzer for JavaScript web repositories and signals."""

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


def get_registered_analyzers() -> list[Analyzer]:
    """Return analyzers known to core.

    Discovery is intentionally simple for now: core exposes its built-in
    analyzer directly and will gain installed-analyzer discovery later.
    """

    # Order matters: specialized analyzers run first, then the fallback analyzer
    # covers any remaining built-in ecosystems that core still understands.
    return [BuiltinPythonWebAnalyzer(), BuiltinJavaScriptWebAnalyzer(), DefaultAnalyzer()]


def get_analyzer_metadata(analyzer: Analyzer) -> AnalyzerMetadata:
    """Return the minimal metadata exposed by an analyzer."""

    return analyzer.metadata


def analyze_repository(root: str | Path, analyzers: Iterable[Analyzer] | None = None) -> AnalyzerResult:
    """Run registered analyzers and merge their structured results."""

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
    """Merge analyzer results into the single normalized shape used by core.

    Strategy:
    - keep the provided root, or fall back to the first analyzer result root
    - combine `files_scanned` by summing analyzer contributions
    - deduplicate obvious duplicate signals by exact structural keys
    - preserve analyzer order for first-seen items

    This stays intentionally simple so the current reporting pipeline can keep
    consuming a single ScanResult without knowing which analyzer contributed
    which signal.
    """

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
