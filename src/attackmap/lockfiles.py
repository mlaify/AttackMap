"""Lockfile resolution for the SBOM/CVE pipeline (#143).

Manifests (``package.json``, ``pyproject.toml`` …) declare version *ranges*
and only direct dependencies. Lockfiles pin *exact* resolved versions and
record the full transitive tree — which is where most known-vulnerable
dependencies actually live. This module parses the common lockfiles into
``DependencyHint`` records with ``resolved=True``, a ``direct`` flag, and a
``via`` resolution path (``"express > body-parser > qs"``) reconstructed from
the dependency graph.

Supported lockfiles:
    - package-lock.json   (npm v1/v2/v3)      → npm
    - pnpm-lock.yaml       (pnpm)             → npm
    - poetry.lock          (Poetry)           → pypi
    - uv.lock              (uv)               → pypi
    - Cargo.lock           (Cargo)            → cargo
    - go.sum               (Go modules)       → go

When a lockfile supersedes a range-only manifest (npm / pypi / cargo), the
manifest hints for that ecosystem are dropped in favour of the exact
resolution — see ``analyze_sbom`` in ``sbom.py``. Go is special: ``go.mod``
already carries exact versions, so go.sum only supplements it.

Parsing is defensive: a malformed lockfile yields ``[]`` rather than raising.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .models import DependencyHint

# Ecosystems whose manifests carry only ranges — a lockfile here fully
# supersedes the manifest. Go is excluded (go.mod is already exact).
SUPERSEDING_ECOSYSTEMS = frozenset({"npm", "pypi", "cargo"})

_LOCKFILE_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
}

_MAX_DEPTH = 4  # slightly deeper than manifests — lockfiles can nest


@dataclass
class _Graph:
    """A resolved dependency graph for one lockfile.

    ``nodes`` maps a package name to ``(version, dev)``. ``edges`` maps a
    package name to the names it depends on. ``roots`` are the direct
    dependencies (entry points for path reconstruction). When a parser cannot
    determine roots explicitly, leave ``roots`` empty and the resolver falls
    back to "a node no one depends on is a root".
    """

    ecosystem: str
    nodes: dict[str, tuple[str, bool]] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    roots: set[str] = field(default_factory=set)


def parse_lockfiles(root: str | Path) -> tuple[list[DependencyHint], set[str]]:
    """Walk ``root`` for lockfiles.

    Returns ``(hints, superseded_ecosystems)`` — the resolved dependency hints
    and the set of ecosystems whose range-only manifests should be dropped.
    """
    root_path = Path(root).resolve()
    if not root_path.exists() or not root_path.is_dir():
        return [], set()

    hints: list[DependencyHint] = []
    superseded: set[str] = set()
    for lockfile in _iter_lockfiles(root_path):
        rel = str(lockfile.relative_to(root_path)).replace("\\", "/")
        try:
            graph = _parse_lockfile(lockfile)
        except (OSError, UnicodeDecodeError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError):
            continue
        if graph is None or not graph.nodes:
            continue
        file_hints = _graph_to_hints(graph, rel)
        for hint in file_hints:
            hint.source_analyzer = "sbom"
        hints.extend(file_hints)
        if graph.ecosystem in SUPERSEDING_ECOSYSTEMS:
            superseded.add(graph.ecosystem)
    return hints, superseded


def _iter_lockfiles(root: Path):
    def walk(directory: Path, depth: int):
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            if entry.name in {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", "target", "vendor"}:
                continue
            if entry.is_dir():
                if depth < _MAX_DEPTH:
                    yield from walk(entry, depth + 1)
            elif entry.name in _LOCKFILE_NAMES:
                yield entry

    yield from walk(root, 1)


def _parse_lockfile(path: Path) -> _Graph | None:
    name = path.name
    if name == "package-lock.json":
        return _parse_package_lock(path)
    if name == "pnpm-lock.yaml":
        return _parse_pnpm_lock(path)
    if name == "poetry.lock":
        return _parse_poetry_lock(path)
    if name == "uv.lock":
        return _parse_uv_lock(path)
    if name == "Cargo.lock":
        return _parse_cargo_lock(path)
    if name == "go.sum":
        return _parse_go_sum(path)
    return None


# --- Graph → hints ---------------------------------------------------------


def _graph_to_hints(graph: _Graph, rel: str) -> list[DependencyHint]:
    """Reconstruct a resolution path for every node and emit hints."""
    roots = graph.roots or _implicit_roots(graph)
    paths = _shortest_paths(graph, roots)
    hints: list[DependencyHint] = []
    for name, (version, dev) in sorted(graph.nodes.items()):
        path = paths.get(name)
        is_direct = name in roots
        via = None
        if path is not None and len(path) > 1:
            via = " > ".join(path)
        hints.append(
            DependencyHint(
                name=name,
                version=version,
                ecosystem=graph.ecosystem,  # type: ignore[arg-type]
                file=rel,
                dev=dev,
                resolved=True,
                direct=is_direct,
                via=via,
                evidence_text=(f"{name}@{version}" if is_direct else f"transitive: {via or name}"),
            )
        )
    return hints


def _implicit_roots(graph: _Graph) -> set[str]:
    """Roots = nodes nothing else depends on (reverse-graph heuristic)."""
    depended_on: set[str] = set()
    for children in graph.edges.values():
        depended_on.update(children)
    roots = {name for name in graph.nodes if name not in depended_on}
    # Degenerate cycle-only graph: fall back to treating every node as a root
    # so nothing is silently dropped from the CVE scan.
    return roots or set(graph.nodes)


def _shortest_paths(graph: _Graph, roots: set[str]) -> dict[str, list[str]]:
    """BFS from every root; record the shortest name-path to each node."""
    paths: dict[str, list[str]] = {r: [r] for r in roots if r in graph.nodes}
    queue: deque[str] = deque(paths)
    while queue:
        current = queue.popleft()
        for child in sorted(graph.edges.get(current, ())):
            if child in paths or child not in graph.nodes:
                continue
            paths[child] = paths[current] + [child]
            queue.append(child)
    return paths


# --- npm: package-lock.json ------------------------------------------------


def _parse_package_lock(path: Path) -> _Graph:
    data = json.loads(path.read_text(encoding="utf-8"))
    graph = _Graph(ecosystem="npm")
    packages = data.get("packages")
    if isinstance(packages, dict):
        _parse_package_lock_v3(packages, graph)
    else:
        _parse_package_lock_v1(data.get("dependencies") or {}, graph)
    return graph


def _pkg_name_from_path(pkg_path: str) -> str | None:
    """`node_modules/a/node_modules/@scope/b` -> `@scope/b`."""
    marker = "node_modules/"
    idx = pkg_path.rfind(marker)
    if idx == -1:
        return None
    return pkg_path[idx + len(marker):]


def _parse_package_lock_v3(packages: dict, graph: _Graph) -> None:
    # The "" entry is the root project; its deps are the direct dependencies.
    root_meta = packages.get("") or {}
    for section, dev in (("dependencies", False), ("devDependencies", True)):
        for dep in (root_meta.get(section) or {}):
            graph.roots.add(dep)
    for pkg_path, meta in packages.items():
        if pkg_path == "" or not isinstance(meta, dict):
            continue
        name = _pkg_name_from_path(pkg_path)
        version = meta.get("version")
        if not name or not isinstance(version, str):
            continue
        dev = bool(meta.get("dev", False))
        graph.nodes[name] = (version, dev)
        children = set()
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            children.update((meta.get(section) or {}).keys())
        if children:
            graph.edges[name] = children


def _parse_package_lock_v1(deps: dict, graph: _Graph, *, is_root: bool = True) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str):
            dev = bool(meta.get("dev", False))
            graph.nodes[name] = (version, dev)
            if is_root:
                graph.roots.add(name)
            requires = meta.get("requires") or {}
            if isinstance(requires, dict) and requires:
                graph.edges.setdefault(name, set()).update(requires.keys())
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _parse_package_lock_v1(nested, graph, is_root=False)


# --- npm: pnpm-lock.yaml ---------------------------------------------------

_PNPM_PKG_KEY_RE = re.compile(r"^/?(?P<name>@?[^@/][^@]*(?:/[^@]+)?)@(?P<version>[^(]+)")


def _parse_pnpm_lock(path: Path) -> _Graph | None:
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a declared dependency
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    graph = _Graph(ecosystem="npm")

    # Roots: importers.'.'.{dependencies,devDependencies} (v6+) or top-level.
    importers = data.get("importers")
    root_sections = []
    if isinstance(importers, dict):
        for imp in importers.values():
            if isinstance(imp, dict):
                root_sections.append(imp)
    else:
        root_sections.append(data)
    for section in root_sections:
        for key in ("dependencies", "devDependencies"):
            deps = section.get(key)
            if isinstance(deps, dict):
                graph.roots.update(deps.keys())

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return graph
    for raw_key, meta in packages.items():
        m = _PNPM_PKG_KEY_RE.match(str(raw_key))
        if not m:
            continue
        name = m.group("name")
        version = m.group("version").strip()
        dev = bool(meta.get("dev", False)) if isinstance(meta, dict) else False
        graph.nodes[name] = (version, dev)
        if isinstance(meta, dict):
            children = set()
            for key in ("dependencies", "optionalDependencies"):
                deps = meta.get(key)
                if isinstance(deps, dict):
                    children.update(deps.keys())
            if children:
                graph.edges[name] = children
    return graph


# --- pypi: poetry.lock / uv.lock; cargo: Cargo.lock (all TOML [[package]]) --


def _parse_toml_packages(path: Path, ecosystem: str) -> _Graph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    graph = _Graph(ecosystem=ecosystem)
    packages = data.get("package")
    if not isinstance(packages, list):
        return graph
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        # poetry marks dev deps with category/groups; uv/cargo don't reliably.
        dev = pkg.get("category") == "dev" or "dev" in (pkg.get("groups") or [])
        graph.nodes[name] = (version, bool(dev))
        graph.edges.setdefault(name, set()).update(_toml_dep_names(pkg.get("dependencies")))
    return graph


def _toml_dep_names(deps) -> set[str]:
    """Extract child names from a lockfile's `dependencies` value.

    Handles poetry's ``{name = "spec"}`` table, uv/cargo's ``[{name=..}]`` and
    cargo's ``["name version …"]`` string list."""
    names: set[str] = set()
    if isinstance(deps, dict):
        names.update(deps.keys())
    elif isinstance(deps, list):
        for item in deps:
            if isinstance(item, str):
                names.add(item.split()[0])  # "name version source" → name
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.add(item["name"])
    return names


def _parse_poetry_lock(path: Path) -> _Graph:
    return _parse_toml_packages(path, "pypi")


def _parse_uv_lock(path: Path) -> _Graph:
    return _parse_toml_packages(path, "pypi")


def _parse_cargo_lock(path: Path) -> _Graph:
    return _parse_toml_packages(path, "cargo")


# --- go: go.sum ------------------------------------------------------------

# `module version hash` and `module version/go.mod hash`.
_GO_SUM_LINE_RE = re.compile(r"^(?P<name>\S+)\s+(?P<version>v\S+?)(?:/go\.mod)?\s+h1:")


def _parse_go_sum(path: Path) -> _Graph:
    graph = _Graph(ecosystem="go")
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = _GO_SUM_LINE_RE.match(raw.strip())
        if not m:
            continue
        name = m.group("name")
        version = m.group("version")
        # go.sum carries no dependency graph and no direct/indirect flag; the
        # richer signal comes from go.mod (parsed as a manifest). Mark these
        # transitive — go.mod's direct entries win when both are present.
        graph.nodes.setdefault(name, (version, False))
    return graph
