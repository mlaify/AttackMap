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

Go is intentionally NOT resolved from ``go.sum``: that file is a checksum
history and can retain modules absent from the current build list, so emitting
every line would over-report. ``go.mod`` already pins exact versions and flags
``// indirect`` deps, so the manifest parser in ``sbom.py`` fully covers Go.

When a lockfile supersedes a range-only manifest, it does so only for the
manifest in the *same directory* — see ``analyze_sbom`` in ``sbom.py``.

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

# Ecosystems whose manifests carry only ranges — a lockfile here supersedes
# the same-directory manifest.
SUPERSEDING_ECOSYSTEMS = frozenset({"npm", "pypi", "cargo"})

_LOCKFILE_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
}

_MAX_DEPTH = 4  # slightly deeper than manifests — lockfiles can nest


@dataclass
class _Graph:
    """A resolved dependency graph for one lockfile.

    ``instances`` maps each distinct installed package ``(name, version)`` to
    its dev flag — keyed by (name, version) so multiple installed versions of
    the same package are all preserved (npm hoisting). ``edges`` and ``roots``
    are name-based (lockfile dependency references are by name), used only for
    best-effort path reconstruction. When a parser can name the direct
    dependencies explicitly it fills ``roots``; otherwise the resolver falls
    back to "a name nothing depends on is a root".
    """

    ecosystem: str
    instances: dict[tuple[str, str], bool] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    roots: set[str] = field(default_factory=set)


def parse_lockfiles(root: str | Path) -> tuple[list[DependencyHint], set[tuple[str, str]]]:
    """Walk ``root`` for lockfiles.

    Returns ``(hints, superseded)`` where ``superseded`` is a set of
    ``(ecosystem, directory)`` pairs — the range-only manifests in those exact
    directories should be dropped in favour of the exact resolution.
    """
    root_path = Path(root).resolve()
    if not root_path.exists() or not root_path.is_dir():
        return [], set()

    hints: list[DependencyHint] = []
    superseded: set[tuple[str, str]] = set()
    for lockfile in _iter_lockfiles(root_path):
        rel = str(lockfile.relative_to(root_path)).replace("\\", "/")
        directory = str(Path(rel).parent).replace("\\", "/")
        try:
            graph = _parse_lockfile(lockfile)
        except (OSError, UnicodeDecodeError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError):
            continue
        if graph is None or not graph.instances:
            continue
        file_hints = _graph_to_hints(graph, rel)
        for hint in file_hints:
            hint.source_analyzer = "sbom"
        hints.extend(file_hints)
        if graph.ecosystem in SUPERSEDING_ECOSYSTEMS:
            superseded.add((graph.ecosystem, directory))
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
    return None


# --- Graph → hints ---------------------------------------------------------


def _graph_to_hints(graph: _Graph, rel: str) -> list[DependencyHint]:
    """Reconstruct a resolution path for every installed instance and emit."""
    names = {name for (name, _v) in graph.instances}
    roots = graph.roots or _implicit_roots(graph, names)
    paths = _shortest_paths(graph, roots, names)
    hints: list[DependencyHint] = []
    for (name, version), dev in sorted(graph.instances.items()):
        path = paths.get(name)
        is_direct = name in roots
        via = " > ".join(path) if path is not None and len(path) > 1 else None
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


def _implicit_roots(graph: _Graph, names: set[str]) -> set[str]:
    """Roots = names nothing else depends on (reverse-graph heuristic)."""
    depended_on: set[str] = set()
    for children in graph.edges.values():
        depended_on.update(children)
    roots = {name for name in names if name not in depended_on}
    # Degenerate cycle-only graph: treat every name as a root so nothing is
    # silently dropped from the CVE scan.
    return roots or set(names)


def _shortest_paths(graph: _Graph, roots: set[str], names: set[str]) -> dict[str, list[str]]:
    """BFS from every root; record the shortest name-path to each name."""
    paths: dict[str, list[str]] = {r: [r] for r in roots if r in names}
    queue: deque[str] = deque(paths)
    while queue:
        current = queue.popleft()
        for child in sorted(graph.edges.get(current, ())):
            if child in paths or child not in names:
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
    for section in ("dependencies", "devDependencies"):
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
        # Keyed by (name, version): a hoisted x@2 and a nested x@1 both survive.
        graph.instances[(name, version)] = graph.instances.get((name, version), False) or dev
        children = set()
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            children.update((meta.get(section) or {}).keys())
        if children:
            graph.edges.setdefault(name, set()).update(children)


def _parse_package_lock_v1(deps: dict, graph: _Graph, *, is_root: bool = True) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str):
            dev = bool(meta.get("dev", False))
            graph.instances[(name, version)] = graph.instances.get((name, version), False) or dev
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
    # pnpm-lock is normally a single YAML document, but some files concatenate
    # several with `---` separators (e.g. a merge artifact, or a tool that
    # appends per-workspace lockfiles). Parse every document and merge them, and
    # never let a malformed-YAML error abort the whole scan — a lockfile we can't
    # read just yields no dependency hints.
    try:
        documents = [
            doc
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict)
        ]
    except yaml.YAMLError:
        return None
    if not documents:
        return None
    graph = _Graph(ecosystem="npm")
    for data in documents:
        _absorb_pnpm_document(data, graph)
    return graph


def _absorb_pnpm_document(data: dict, graph: _Graph) -> None:
    """Fold one parsed pnpm-lock YAML document into ``graph`` (roots + packages)."""
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
        return
    for raw_key, meta in packages.items():
        m = _PNPM_PKG_KEY_RE.match(str(raw_key))
        if not m:
            continue
        name = m.group("name")
        version = m.group("version").strip()
        dev = bool(meta.get("dev", False)) if isinstance(meta, dict) else False
        graph.instances[(name, version)] = graph.instances.get((name, version), False) or dev
        if isinstance(meta, dict):
            children = set()
            for key in ("dependencies", "optionalDependencies"):
                deps = meta.get(key)
                if isinstance(deps, dict):
                    children.update(deps.keys())
            if children:
                graph.edges.setdefault(name, set()).update(children)


# --- pypi: poetry.lock / uv.lock; cargo: Cargo.lock (all TOML [[package]]) --


def _parse_toml_packages(path: Path, ecosystem: str) -> _Graph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    graph = _Graph(ecosystem=ecosystem)
    packages = data.get("package")
    if not isinstance(packages, list):
        return graph

    # First pass: collect entries and identify local/workspace packages (the
    # repo's own crates/projects). These are NOT third-party deps — their
    # direct dependencies are the project's direct dependencies.
    entries: list[tuple[str, str, bool, bool, set[str]]] = []
    direct_names: set[str] = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        dev = pkg.get("category") == "dev" or "dev" in (pkg.get("groups") or [])
        deps = _toml_dep_names(pkg.get("dependencies"))
        is_local = _is_local_toml_pkg(pkg, ecosystem)
        entries.append((name, version, bool(dev), is_local, deps))
        if is_local:
            direct_names.update(deps)

    for name, version, dev, is_local, deps in entries:
        if is_local:
            continue  # the project itself is not an SBOM entry
        graph.instances[(name, version)] = graph.instances.get((name, version), False) or dev
        if deps:
            graph.edges.setdefault(name, set()).update(deps)
    graph.roots = direct_names  # empty → resolver falls back to reverse-graph
    return graph


def _is_local_toml_pkg(pkg: dict, ecosystem: str) -> bool:
    """True for the repo's own crate/project entry (not a third-party dep).

    Cargo workspace members have no ``source``; uv's project package has an
    editable/virtual source. Poetry never lists the root project in its lock.
    """
    source = pkg.get("source")
    if ecosystem == "cargo":
        return source is None
    if ecosystem == "pypi":  # uv.lock
        return isinstance(source, dict) and ("editable" in source or "virtual" in source)
    return False


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
