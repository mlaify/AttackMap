"""Plugin recommendation UX (#46).

Walks a repository lightly, spots ecosystem markers (manifest files,
extensions, config directories), and maps each to the AttackMap plugin
that would give the deepest signal for it.

The output is a ranked list of pip install lines. Ranking is by matched
signal count (more matches = stronger recommendation) with plugin name
as tiebreaker for stable output.

Detector philosophy:
    - Prefer manifest files (``pyproject.toml``, ``go.mod``, ``Cargo.toml``,
      ``composer.json``) over raw file globs — a directory full of ``*.py``
      inside a Rails project shouldn't recommend the Python analyzer.
    - Cap directory walk depth so a monorepo doesn't cost seconds.
    - Never touch the network. Never introspect the file content beyond
      the small ``composer.json`` / ``package.json`` peek that decides
      between generic and framework-specific plugins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .analyzers import get_available_modules

# Depth cap for the recursive walk. Enough for a monorepo's top-level
# packages/services/apps folders; not enough to explore node_modules.
_MAX_DEPTH = 3

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
    "target",
    "vendor",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
}


@dataclass(frozen=True)
class Suggestion:
    """One plugin recommendation for the repo."""

    plugin: str  # PyPI package name, e.g. "attackmap-analyzer-python"
    analyzer_name: str  # Analyzer entry-point name, e.g. "python"
    matched_signals: tuple[str, ...]
    installed: bool = False

    @property
    def pip_install(self) -> str:
        return f"pip install {self.plugin}"


@dataclass(frozen=True)
class _Detector:
    plugin: str
    analyzer_name: str
    manifest_files: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    directory_names: tuple[str, ...] = ()
    # A callable that receives (root, manifest_paths_by_name, extension_hits)
    # and returns extra matched signals or an empty list. Used for framework
    # discrimination (Spring vs generic Java, Laminas vs generic PHP).
    extra: object = None


def _spring_extras(
    root: Path,
    manifests: dict[str, list[Path]],
    _exts: dict[str, list[Path]],
) -> list[str]:
    for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        for p in manifests.get(name, ()):
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "org.springframework" in text or "spring-boot" in text:
                return [f"{name} references Spring"]
    return []


# Manifest names that extras callbacks read even though no detector's
# `manifest_files` demands the whole-file trigger. `_sweep` still collects
# them so ``manifests.get(name)`` in the callbacks returns hits.
_EXTRAS_MANIFESTS = ("pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "package.json")


def _laminas_extras(
    root: Path,
    manifests: dict[str, list[Path]],
    _exts: dict[str, list[Path]],
) -> list[str]:
    for p in manifests.get("composer.json", ()):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        deps: dict = {}
        for key in ("require", "require-dev"):
            section = data.get(key) or {}
            if isinstance(section, dict):
                deps.update(section)
        if any(k.startswith("laminas/") or k.startswith("zendframework/") for k in deps):
            return ["composer.json depends on laminas/*"]
    return []


def _omeka_extras(
    root: Path,
    manifests: dict[str, list[Path]],
    _exts: dict[str, list[Path]],
) -> list[str]:
    for p in manifests.get("composer.json", ()):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        deps: dict = {}
        for key in ("require", "require-dev"):
            section = data.get(key) or {}
            if isinstance(section, dict):
                deps.update(section)
        if any(k.startswith("omeka/") for k in deps):
            return ["composer.json depends on omeka/*"]
    # Fallback structural cue: an Omeka-S module tends to ship
    # `config/module.config.php` alongside `Module.php`.
    if (root / "config" / "module.config.php").exists() and (root / "Module.php").exists():
        return ["Omeka-S module layout (config/module.config.php + Module.php)"]
    return []


def _atproto_extras(
    root: Path,
    manifests: dict[str, list[Path]],
    _exts: dict[str, list[Path]],
) -> list[str]:
    hits: list[str] = []
    for p in manifests.get("package.json", ()):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        deps: dict = {}
        for key in ("dependencies", "devDependencies"):
            section = data.get(key) or {}
            if isinstance(section, dict):
                deps.update(section)
        if any(k.startswith("@atproto/") for k in deps):
            hits.append("package.json depends on @atproto/*")
            break
    if (root / "lexicons").is_dir():
        hits.append("lexicons/ directory present")
    return hits


def _php_web_extras(
    _root: Path,
    manifests: dict[str, list[Path]],
    _exts: dict[str, list[Path]],
) -> list[str]:
    # Only recommend the generic PHP-web plugin when we didn't already
    # see a framework marker — the caller strips this hit in that case.
    if manifests.get("composer.json"):
        return ["composer.json present (generic PHP web app)"]
    return []


DETECTORS: tuple[_Detector, ...] = (
    _Detector(
        plugin="attackmap-analyzer-python",
        analyzer_name="python",
        manifest_files=("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile"),
        extensions=(".py",),
    ),
    _Detector(
        plugin="attackmap-analyzer-node-service",
        analyzer_name="node-service",
        manifest_files=("package.json", "tsconfig.json", "pnpm-lock.yaml", "yarn.lock"),
        extensions=(".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"),
    ),
    _Detector(
        plugin="attackmap-analyzer-atproto",
        analyzer_name="atproto",
        extra=_atproto_extras,
    ),
    _Detector(
        plugin="attackmap-analyzer-go",
        analyzer_name="go",
        manifest_files=("go.mod", "go.sum"),
        extensions=(".go",),
    ),
    _Detector(
        plugin="attackmap-analyzer-rust",
        analyzer_name="rust",
        manifest_files=("Cargo.toml", "Cargo.lock"),
        extensions=(".rs",),
    ),
    _Detector(
        plugin="attackmap-analyzer-java-spring",
        analyzer_name="java-spring",
        # No manifest_files here on purpose: a plain Maven pom.xml
        # without a Spring dependency should NOT recommend the Spring
        # analyzer. The extras callback opens the manifests and only
        # returns a signal when it finds an actual Spring reference.
        extra=_spring_extras,
    ),
    _Detector(
        plugin="attackmap-analyzer-dotnet",
        analyzer_name="dotnet",
        manifest_files=("Directory.Build.props", "global.json"),
        extensions=(".cs", ".csproj", ".sln"),
    ),
    _Detector(
        plugin="attackmap-analyzer-terraform",
        analyzer_name="terraform",
        extensions=(".tf", ".tfvars"),
    ),
    _Detector(
        plugin="attackmap-analyzer-c",
        analyzer_name="c",
        manifest_files=("configure.ac", "Makefile.am", "Makefile"),
        extensions=(".c", ".h"),
    ),
    _Detector(
        plugin="attackmap-analyzer-cpp",
        analyzer_name="cpp",
        manifest_files=("CMakeLists.txt",),
        extensions=(".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
    ),
    _Detector(
        plugin="attackmap-analyzer-php-laminas",
        analyzer_name="php-laminas",
        extra=_laminas_extras,
    ),
    _Detector(
        plugin="attackmap-analyzer-omeka-s",
        analyzer_name="omeka-s",
        extra=_omeka_extras,
    ),
    _Detector(
        plugin="attackmap-analyzer-php-web",
        analyzer_name="php-web",
        extra=_php_web_extras,
        extensions=(".php",),
    ),
    _Detector(
        plugin="attackmap-analyzer-iac",
        analyzer_name="iac",
        manifest_files=(
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ),
        directory_names=(".github/workflows",),
    ),
)


def detect_ecosystems(root: str | Path) -> list[Suggestion]:
    """Walk ``root`` shallowly, return a ranked list of plugin suggestions."""
    root_path = Path(root).resolve()
    if not root_path.exists() or not root_path.is_dir():
        return []

    manifests, extensions_hit, directories_hit = _sweep(root_path)
    installed_names = _installed_analyzer_names()

    suggestions: list[Suggestion] = []
    php_framework_seen = False

    for detector in DETECTORS:
        signals: list[str] = []
        for name in detector.manifest_files:
            if manifests.get(name):
                first = manifests[name][0].relative_to(root_path)
                signals.append(str(first))
        for ext in detector.extensions:
            if extensions_hit.get(ext):
                sample = extensions_hit[ext][0].relative_to(root_path)
                signals.append(f"{ext} sources (e.g. {sample})")
        for dir_name in detector.directory_names:
            if dir_name in directories_hit:
                signals.append(f"{dir_name}/ present")
        if callable(detector.extra):
            signals.extend(detector.extra(root_path, manifests, extensions_hit))

        # Framework-specific PHP hits (laminas, omeka-s) suppress the
        # generic PHP-web recommendation — otherwise a Laminas project
        # ends up with both.
        if detector.plugin in {"attackmap-analyzer-php-laminas", "attackmap-analyzer-omeka-s"} and signals:
            php_framework_seen = True
        if detector.plugin == "attackmap-analyzer-php-web" and php_framework_seen:
            continue

        if not signals:
            continue

        suggestions.append(
            Suggestion(
                plugin=detector.plugin,
                analyzer_name=detector.analyzer_name,
                matched_signals=tuple(signals),
                installed=detector.analyzer_name in installed_names,
            )
        )

    suggestions.sort(key=lambda s: (-len(s.matched_signals), s.plugin))
    return suggestions


def _sweep(
    root: Path,
) -> tuple[dict[str, list[Path]], dict[str, list[Path]], set[str]]:
    manifests: dict[str, list[Path]] = {}
    extensions: dict[str, list[Path]] = {}
    directories: set[str] = set()

    interesting_manifests = {
        name for detector in DETECTORS for name in detector.manifest_files
    }
    interesting_manifests.update(_EXTRAS_MANIFESTS)
    interesting_directories = {
        name for detector in DETECTORS for name in detector.directory_names
    }
    interesting_exts = {ext for detector in DETECTORS for ext in detector.extensions}

    # Note: `.github/workflows` is a two-segment name; check it explicitly.
    if (root / ".github" / "workflows").is_dir():
        directories.add(".github/workflows")

    for path in _iter_paths(root):
        if path.is_dir():
            rel = path.relative_to(root).as_posix()
            if rel in interesting_directories:
                directories.add(rel)
            continue
        if path.name in interesting_manifests:
            manifests.setdefault(path.name, []).append(path)
            continue
        suffix = path.suffix
        if suffix in interesting_exts:
            extensions.setdefault(suffix, []).append(path)

    return manifests, extensions, directories


def _iter_paths(root: Path):
    """Depth-capped, dot-skipping traversal used by the sweep."""

    def walk(directory: Path, depth: int):
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            name = entry.name
            if name in _SKIP_DIRS:
                continue
            if entry.is_dir():
                yield entry
                if depth < _MAX_DEPTH:
                    yield from walk(entry, depth + 1)
            else:
                yield entry

    yield from walk(root, 1)


def _installed_analyzer_names() -> set[str]:
    try:
        return {module.name for module in get_available_modules()}
    except Exception:  # pragma: no cover — never let CLI ergonomics crash on registry failure
        return set()
