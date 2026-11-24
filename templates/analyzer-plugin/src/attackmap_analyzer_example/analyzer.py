"""Example analyzer: routes declared as `@route("GET", "/path")` in `.ex` files."""

from __future__ import annotations

import re
from pathlib import Path

from attackmap.sdk import (
    AnalyzerMetadata,
    Route,
    ScanResult,
    SignalCollector,
    iter_repo_files,
    line_of,
    plugin_version,
    read_source,
    rel,
)

_ROUTE_RE = re.compile(r'@route\(\s*"(GET|POST|PUT|PATCH|DELETE)"\s*,\s*"(/[^"]*)"\s*\)')


class ExampleAnalyzer:
    metadata = AnalyzerMetadata(
        name="example",
        display_name="Example",
        version=plugin_version("attackmap-analyzer-example", default="0.1.0"),
        description="Routes declared with @route(...) in .ex files.",
        languages=["example"],
        requires_core=">=0.8,<2",
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        return any(True for _ in iter_repo_files(repo_path, suffixes={".ex"}))

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path)
        result = ScanResult(root=str(root))
        signals = SignalCollector(result)
        for path in iter_repo_files(root, suffixes={".ex"}):
            content = read_source(path, root=root)
            if content is None:
                continue
            for m in _ROUTE_RE.finditer(content):
                signals.add(Route(path=m.group(2), method=m.group(1), file=rel(path, root), line=line_of(content, m.start())))
        return result
