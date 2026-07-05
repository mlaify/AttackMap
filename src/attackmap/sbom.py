"""SBOM inventory (slice 1 of #48).

Scans a repository for dependency manifests and emits a
``DependencyHint`` per declared third-party package. Direct dependencies
only — no lockfile resolution, no transitive walk. Version ranges are
kept verbatim (``^4.16.0``, ``>=2,<3``, etc.); consumers that need a
resolved version look at lockfiles (deferred slice).

Supported ecosystems:
    - pypi        pyproject.toml (PEP 621) + requirements.txt
    - npm         package.json (dependencies + devDependencies)
    - go          go.mod (require blocks)
    - cargo       Cargo.toml ([dependencies] + [dev-dependencies])
    - composer    composer.json (require + require-dev)

CVE lookup is intentionally NOT here — it's a separate ticket (see the
follow-up filed with the PR that lands this slice) because it requires
network I/O, on-disk caching, and rate limiting.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .models import DependencyHint

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
}


def analyze_sbom(root: str | Path) -> list[DependencyHint]:
    """Walk ``root`` and return a deduped list of DependencyHint records."""
    root_path = Path(root).resolve()
    if not root_path.exists() or not root_path.is_dir():
        return []

    hints: list[DependencyHint] = []
    for manifest in _iter_manifests(root_path):
        rel = str(manifest.relative_to(root_path)).replace("\\", "/")
        try:
            hints.extend(_parse_manifest(manifest, rel))
        except (OSError, UnicodeDecodeError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError):
            # A malformed manifest shouldn't sink the whole scan; skip it.
            continue

    for hint in hints:
        hint.source_analyzer = "sbom"

    return _dedup(hints)


def _iter_manifests(root: Path):
    """Depth-capped walk yielding candidate manifest files by name."""

    interesting = {
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "go.mod",
        "Cargo.toml",
        "composer.json",
    }

    def walk(directory: Path, depth: int):
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            if entry.name in _SKIP_DIRS:
                continue
            if entry.is_dir():
                if depth < _MAX_DEPTH:
                    yield from walk(entry, depth + 1)
            elif entry.name in interesting:
                yield entry

    yield from walk(root, 1)


def _parse_manifest(path: Path, rel: str) -> list[DependencyHint]:
    name = path.name
    if name == "pyproject.toml":
        return _parse_pyproject(path, rel)
    if name == "requirements.txt":
        return _parse_requirements(path, rel)
    if name == "package.json":
        return _parse_package_json(path, rel)
    if name == "go.mod":
        return _parse_go_mod(path, rel)
    if name == "Cargo.toml":
        return _parse_cargo_toml(path, rel)
    if name == "composer.json":
        return _parse_composer_json(path, rel)
    return []


# ---------- Python ---------------------------------------------------------


_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_pyproject(path: Path, rel: str) -> list[DependencyHint]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project") or {}
    hints: list[DependencyHint] = []
    for spec in project.get("dependencies") or []:
        parsed = _parse_pep508(str(spec))
        if parsed:
            name, version = parsed
            hints.append(DependencyHint(name=name, version=version, ecosystem="pypi", file=rel, evidence_text=str(spec)))
    optional: dict = project.get("optional-dependencies") or {}
    for group_name, specs in optional.items():
        is_dev = group_name.lower() in {"dev", "test", "tests", "lint", "docs"}
        for spec in specs or []:
            parsed = _parse_pep508(str(spec))
            if parsed:
                name, version = parsed
                hints.append(
                    DependencyHint(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        file=rel,
                        dev=is_dev,
                        evidence_text=f"[{group_name}] {spec}",
                    )
                )
    # Poetry (still fairly common); tool.poetry.dependencies is a dict.
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for spec_name, spec_value in (poetry.get("dependencies") or {}).items():
        if spec_name.lower() == "python":
            continue
        version = _stringify_poetry_version(spec_value)
        hints.append(
            DependencyHint(
                name=spec_name,
                version=version,
                ecosystem="pypi",
                file=rel,
                evidence_text=f"tool.poetry.dependencies.{spec_name} = {spec_value!r}",
            )
        )
    for spec_name, spec_value in (poetry.get("dev-dependencies") or {}).items():
        version = _stringify_poetry_version(spec_value)
        hints.append(
            DependencyHint(
                name=spec_name,
                version=version,
                ecosystem="pypi",
                file=rel,
                dev=True,
                evidence_text=f"tool.poetry.dev-dependencies.{spec_name} = {spec_value!r}",
            )
        )
    return hints


def _parse_pep508(spec: str) -> tuple[str, str] | None:
    """PEP 508 spec → (name, version-or-marker-part)."""
    stripped = spec.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _REQUIREMENT_NAME_RE.match(stripped)
    if not match:
        return None
    name = match.group(1)
    remainder = stripped[match.end():].strip()
    # Cut off env markers (`; python_version < '3.10'`) — they aren't a version.
    if ";" in remainder:
        remainder = remainder.split(";", 1)[0].strip()
    # Extras: `foo[bar]`
    if remainder.startswith("["):
        close = remainder.find("]")
        if close != -1:
            remainder = remainder[close + 1 :].strip()
    version = remainder if remainder else "*"
    return name, version


def _stringify_poetry_version(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("version") or "*")
    return "*"


def _parse_requirements(path: Path, rel: str) -> list[DependencyHint]:
    hints: list[DependencyHint] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-"):
            # -r / -e / -c / --index-url etc. — skip; not a dep declaration.
            continue
        parsed = _parse_pep508(line)
        if parsed:
            name, version = parsed
            hints.append(
                DependencyHint(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    file=rel,
                    line=lineno,
                    evidence_text=line,
                )
            )
    return hints


# ---------- Node -----------------------------------------------------------


def _parse_package_json(path: Path, rel: str) -> list[DependencyHint]:
    data = json.loads(path.read_text(encoding="utf-8"))
    hints: list[DependencyHint] = []
    for section, is_dev in (("dependencies", False), ("devDependencies", True), ("peerDependencies", False), ("optionalDependencies", False)):
        section_data = data.get(section) or {}
        if not isinstance(section_data, dict):
            continue
        for name, version in section_data.items():
            hints.append(
                DependencyHint(
                    name=str(name),
                    version=str(version),
                    ecosystem="npm",
                    file=rel,
                    dev=is_dev,
                    evidence_text=f"{section}.{name} = {version!r}",
                )
            )
    return hints


# ---------- Go -------------------------------------------------------------


_GO_REQUIRE_LINE_RE = re.compile(
    r"^\s*(?P<name>[^\s]+)\s+(?P<version>v[^\s]+)"
)


def _parse_go_mod(path: Path, rel: str) -> list[DependencyHint]:
    """Parse `require` directives in go.mod (both single-line and block form)."""
    text = path.read_text(encoding="utf-8")
    hints: list[DependencyHint] = []
    in_block = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block:
            body = stripped.split("//", 1)[0].strip()
            m = _GO_REQUIRE_LINE_RE.match(body)
            if m:
                is_indirect = "// indirect" in raw
                hints.append(
                    DependencyHint(
                        name=m.group("name"),
                        version=m.group("version"),
                        ecosystem="go",
                        file=rel,
                        line=lineno,
                        dev=is_indirect,
                        evidence_text=raw.strip(),
                    )
                )
            continue
        if stripped.startswith("require "):
            # single-line: `require module/name v1.2.3`
            body = stripped[len("require "):].split("//", 1)[0].strip()
            m = _GO_REQUIRE_LINE_RE.match(body)
            if m:
                hints.append(
                    DependencyHint(
                        name=m.group("name"),
                        version=m.group("version"),
                        ecosystem="go",
                        file=rel,
                        line=lineno,
                        evidence_text=raw.strip(),
                    )
                )
    return hints


# ---------- Rust -----------------------------------------------------------


def _parse_cargo_toml(path: Path, rel: str) -> list[DependencyHint]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    hints: list[DependencyHint] = []
    for section, is_dev in (
        ("dependencies", False),
        ("dev-dependencies", True),
        ("build-dependencies", True),
    ):
        section_data = data.get(section) or {}
        if not isinstance(section_data, dict):
            continue
        for name, spec in section_data.items():
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = str(spec.get("version") or "*")
            else:
                version = "*"
            hints.append(
                DependencyHint(
                    name=str(name),
                    version=version,
                    ecosystem="cargo",
                    file=rel,
                    dev=is_dev,
                    evidence_text=f"[{section}] {name} = {spec!r}",
                )
            )
    return hints


# ---------- PHP ------------------------------------------------------------


def _parse_composer_json(path: Path, rel: str) -> list[DependencyHint]:
    data = json.loads(path.read_text(encoding="utf-8"))
    hints: list[DependencyHint] = []
    for section, is_dev in (("require", False), ("require-dev", True)):
        section_data = data.get(section) or {}
        if not isinstance(section_data, dict):
            continue
        for name, version in section_data.items():
            # composer.json's own "php" / "ext-*" entries are runtime
            # requirements, not third-party packages — skip.
            if name.lower() == "php" or name.lower().startswith("ext-") or name.lower().startswith("lib-"):
                continue
            hints.append(
                DependencyHint(
                    name=str(name),
                    version=str(version),
                    ecosystem="composer",
                    file=rel,
                    dev=is_dev,
                    evidence_text=f"{section}.{name} = {version!r}",
                )
            )
    return hints


# ---------- Dedup ----------------------------------------------------------


def _dedup(hints: list[DependencyHint]) -> list[DependencyHint]:
    seen: set[tuple[str, str, str, str, bool]] = set()
    out: list[DependencyHint] = []
    for h in hints:
        key = (h.ecosystem, h.name, h.version, h.file, h.dev)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out
