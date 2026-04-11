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


def scan_repo(root: str | Path) -> ScanResult:
    """Core scanning entrypoint: discover files, run analyzers, and merge signals."""
    root_path = Path(root).resolve()
    result = ScanResult(root=str(root_path))
    analyzers = get_builtin_analyzers()

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
