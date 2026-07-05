"""Lite data-flow / taint analysis via import-graph walking (#45).

Attack paths today infer flow from file-locality (route + database in the
same file → likely reachable). That heuristic misses the common case
where the handler in ``routes/orders.py`` calls a service in
``services/orders.py`` that touches the database in ``db/orders.py``.

This module builds a per-file import graph for Python and JS/TS, walks
up to N hops from each route-handler file, and emits a ``TaintChain``
for each reachable sink.

Sinks it seeds:
    - ``sql_execute``     — ``.execute(`` / ``.query(`` on a cursor,
                            session, or connection-shaped receiver
    - ``subprocess_shell`` — ``subprocess.run/call/Popen(..., shell=True)``
                            or Node ``child_process.exec(...)``
    - ``eval``            — Python or JS ``eval(...)``
    - ``exec``            — Python ``exec(...)``
    - ``dynamic_open``    — ``open(...)`` whose argument looks derived
                            from a request-shaped identifier

Import != call. Dynamic dispatch, DI containers, and duck-typed
callables aren't followed. Treat findings as evidence, not proof — the
``confidence`` field encodes that, and downstream chain builders should
raise confidence when a matching taint chain exists rather than replace
their own signals with taint alone.
"""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path

from .models import Route, ScanResult, TaintChain

_MAX_HOPS = 2
# Bound the sweep so a deeply-linked monorepo can't blow up the scan.
_MAX_FILES_VISITED_PER_ROUTE = 40

_PY_SUFFIXES = {".py"}
_JS_TS_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_SUPPORTED_SUFFIXES = _PY_SUFFIXES | _JS_TS_SUFFIXES

# --- Import extraction -----------------------------------------------------

_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+(?P<from_mod>[\w.]+)\s+import\b|import\s+(?P<mod>[\w., ]+))",
    re.MULTILINE,
)

# Only relative or bare-word imports we can resolve within the repo.
_JS_IMPORT_RE = re.compile(
    r"""(?:^|\s|;)                   # boundary
        (?:import\s+(?:[^"';]+?\s+from\s+)?|require\s*\(\s*)
        ["'](?P<path>[./][^"']+)["']
    """,
    re.VERBOSE,
)

# --- Sink patterns ---------------------------------------------------------

# Request-shaped identifiers. Used to gate sinks that are only dangerous
# when they consume attacker-controlled input (open, outbound HTTP,
# template render, Mongo filter). Sinks that are dangerous regardless
# (eval, exec, deserialization) don't reference this — reachability from
# a route is enough.
#
# Deliberately conservative. The precise signal for "attacker-controlled"
# is a *member access or subscript on a request container* —
# `req.query.url`, `request.args['x']`, `body['id']`, `params.slug` — not
# a bare identifier. Gating on a bare token drowns real findings: the JS
# Fetch API idiom `fetch(request)` takes a `Request` object literally
# named `request`, and generic names like `url`/`path`/`target` match
# nearly every outbound call (observed 600+ false SSRF hits on a real
# repo before this was tightened). Requiring the trailing `.`/`[` cuts
# that noise while keeping the genuine `req.query.url` shape.
#
# `_TAINTED` = a request container token immediately followed by property
# access (`.field`) or subscript (`[`). We accept lower recall for far
# higher precision; true data-flow to a variable's origin is out of scope
# for this heuristic engine.
_TAINTED = (
    r"(?:req|request|body|query|params|payload|user_input|user_data|form_data)"
    r"\s*(?:\.\s*\w|\[)"
)


_SINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "sql_execute",
        re.compile(
            r"\b(?:cursor|conn|connection|db|session|engine|client|pool)"
            r"\.(?:execute|query|exec_driver_sql)\s*\(",
        ),
    ),
    (
        "subprocess_shell",
        re.compile(
            r"subprocess\.(?:run|call|Popen|check_output|check_call)"
            r"\s*\([^)]*shell\s*=\s*True",
            re.DOTALL,
        ),
    ),
    (
        "subprocess_shell",
        re.compile(r"child_process\s*\.\s*exec\s*\("),
    ),
    (
        "eval",
        re.compile(r"(?<![\w.])eval\s*\("),
    ),
    (
        "exec",
        re.compile(r"(?<![\w.])exec\s*\("),
    ),
    (
        "dynamic_open",
        # `open(...)` with a request-shaped identifier in the args
        # (heuristic; misses variables assigned from tainted input).
        re.compile(rf"(?<![\w.])open\s*\([^)]*{_TAINTED}"),
    ),
    # --- unsafe deserialization (#68) --------------------------------------
    # Dangerous regardless of args: attacker-controlled bytes into any of
    # these is arbitrary-code / object-injection territory.
    (
        "unsafe_deserialization",
        # pickle / cPickle .load / .loads
        re.compile(r"\b(?:cPickle|pickle)\.loads?\s*\("),
    ),
    (
        "unsafe_deserialization",
        # yaml.load WITHOUT a Safe loader in the same call, plus the
        # explicitly-unsafe helper.
        re.compile(r"\byaml\.load\s*\((?![^)]*(?:Safe|Loader\s*=))"),
    ),
    (
        "unsafe_deserialization",
        re.compile(r"\byaml\.unsafe_load\s*\("),
    ),
    (
        "unsafe_deserialization",
        re.compile(r"\bmarshal\.loads?\s*\("),
    ),
    (
        "unsafe_deserialization",
        # Ruby Marshal.load, Java ObjectInputStream, PHP unserialize,
        # JS node-serialize .unserialize
        re.compile(r"\bMarshal\.load\s*\(|\bObjectInputStream\b|\bunserialize\s*\("),
    ),
    # --- server-side template injection (#68) ------------------------------
    (
        "ssti",
        # Flask/Jinja render_template_string with request-shaped input,
        # or a Jinja Template() constructed straight from request input.
        re.compile(rf"\brender_template_string\s*\([^)]*{_TAINTED}"),
    ),
    (
        "ssti",
        re.compile(rf"\bTemplate\s*\([^)]*{_TAINTED}"),
    ),
    # --- server-side request forgery (#68) ---------------------------------
    # Outbound HTTP where a request container access flows into the call.
    # A constant URL is fine, so these are gated on _TAINTED.
    (
        "ssrf",
        re.compile(
            rf"\brequests\.(?:get|post|put|delete|patch|head|request)\s*\([^)]*{_TAINTED}"
        ),
    ),
    (
        "ssrf",
        re.compile(rf"\bhttpx\.(?:get|post|put|delete|patch|head|request|Client)\s*\([^)]*{_TAINTED}"),
    ),
    (
        "ssrf",
        re.compile(rf"\b(?:urlopen|urlretrieve)\s*\([^)]*{_TAINTED}"),
    ),
    (
        "ssrf",
        # JS: axios.get(req...), fetch(req...), http.get(req...)
        re.compile(
            rf"\b(?:axios\s*\.\s*(?:get|post|put|delete|patch|head|request)|fetch|http\.(?:get|request))\s*\([^)]*{_TAINTED}"
        ),
    ),
    # --- NoSQL injection (#68) ---------------------------------------------
    (
        "nosql_injection",
        # Passing a request object straight into a Mongo query filter.
        re.compile(
            rf"\.(?:find|findOne|findOneAndUpdate|update|updateOne|updateMany|remove|deleteOne|deleteMany|aggregate|count|countDocuments)\s*\(\s*{_TAINTED}"
        ),
    ),
    (
        "nosql_injection",
        # $where with any interpolation is an injection risk.
        re.compile(r"\$where"),
    ),
    # --- open redirect (#77) -----------------------------------------------
    # A request-derived value flowing into a redirect. Constant redirect
    # targets are fine, so gated on a request container access.
    (
        "open_redirect",
        re.compile(rf"\bredirect\s*\([^)]*{_TAINTED}"),
    ),
    (
        "open_redirect",
        # Express/Koa: res.redirect(req.query.url) ; also res.location(...)
        re.compile(rf"\bres\s*\.\s*(?:redirect|location)\s*\([^)]*{_TAINTED}"),
    ),
)


# --- Public API ------------------------------------------------------------


def analyze_taint(scan: ScanResult, root: str | Path | None = None) -> list[TaintChain]:
    """Walk the import graph from each route's file, emit TaintChains.

    ``scan.routes`` is treated as the source list. The walk is bounded by
    ``_MAX_HOPS`` and ``_MAX_FILES_VISITED_PER_ROUTE``; duplicate
    (route, sink_file, sink_kind, sink_line) tuples are collapsed.
    """
    root_path = Path(root or scan.root).resolve()
    if not root_path.exists():
        return []

    files = _index_repo(root_path)
    if not files:
        return []

    graph = _build_import_graph(files, root_path)
    sinks_by_file = _find_sinks(files, root_path)

    seen: set[tuple[str, str, str, int | None]] = set()
    chains: list[TaintChain] = []

    for route in scan.routes:
        route_file = _normalize_rel(route.file)
        if route_file not in files:
            continue
        for chain in _walk_from_route(route, route_file, graph, sinks_by_file):
            key = (
                f"{chain.route_method} {chain.route_path}",
                chain.sink_file,
                chain.sink_kind,
                chain.sink_line,
            )
            if key in seen:
                continue
            seen.add(key)
            chain.source_analyzer = "taint"
            chains.append(chain)

    chains.sort(key=lambda c: (c.hops, c.route_file, c.sink_file))
    return chains


# --- Internals -------------------------------------------------------------


def _index_repo(root: Path) -> dict[str, Path]:
    """Return {rel_path: abs_path} for every taint-relevant source file."""
    out: dict[str, Path] = {}
    skip_dirs = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in _SUPPORTED_SUFFIXES:
            continue
        try:
            if any(part in skip_dirs for part in path.relative_to(root).parts):
                continue
        except ValueError:
            continue
        rel = _normalize_rel(str(path.relative_to(root)))
        out[rel] = path
    return out


def _normalize_rel(rel: str) -> str:
    return rel.replace("\\", "/")


def _build_import_graph(files: dict[str, Path], root: Path) -> dict[str, set[str]]:
    """rel_path -> set of rel_paths this file imports (intra-repo only)."""
    graph: dict[str, set[str]] = {rel: set() for rel in files}
    for rel, abs_path in files.items():
        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if abs_path.suffix in _PY_SUFFIXES:
            graph[rel].update(_resolve_py_imports(content, rel, files))
        else:
            graph[rel].update(_resolve_js_imports(content, rel, files, root))
    return graph


def _resolve_py_imports(content: str, from_rel: str, files: dict[str, Path]) -> set[str]:
    from_path = Path(from_rel)
    package_parts = from_path.parent.parts  # containing package as parts
    out: set[str] = set()
    for match in _PY_IMPORT_RE.finditer(content):
        module = match.group("from_mod")
        names_only = match.group("mod")
        if module:
            candidates = [module]
        elif names_only:
            candidates = [n.strip().split(" as ")[0].split(".")[0] for n in names_only.split(",")]
        else:
            continue
        for candidate in candidates:
            resolved = _resolve_py_module(candidate, package_parts, files)
            if resolved is not None:
                out.add(resolved)
    return out


def _resolve_py_module(
    module: str, package_parts: tuple[str, ...], files: dict[str, Path]
) -> str | None:
    parts = module.split(".")
    init_parts = parts + ["__init__.py"]
    # Try as-if fully qualified relative to repo root.
    candidates: list[str] = []
    candidates.append("/".join(parts) + ".py")
    candidates.append("/".join(init_parts))
    # Try relative to package (siblings).
    if package_parts:
        pkg = "/".join(package_parts)
        candidates.append(f"{pkg}/{'/'.join(parts)}.py")
        candidates.append(f"{pkg}/{'/'.join(init_parts)}")
    for cand in candidates:
        norm = _normalize_rel(cand)
        if norm in files:
            return norm
    return None


def _resolve_js_imports(
    content: str, from_rel: str, files: dict[str, Path], root: Path
) -> set[str]:
    from_dir = (root / from_rel).parent
    out: set[str] = set()
    for match in _JS_IMPORT_RE.finditer(content):
        raw = match.group("path")
        target = (from_dir / raw).resolve()
        rel = _resolve_js_target(target, files, root)
        if rel is not None:
            out.add(rel)
    return out


def _resolve_js_target(target: Path, files: dict[str, Path], root: Path) -> str | None:
    # Direct suffixed hit.
    for suffix in _JS_TS_SUFFIXES:
        candidate = target.with_suffix(suffix) if target.suffix else target.parent / (target.name + suffix)
        try:
            rel = _normalize_rel(str(candidate.relative_to(root)))
        except ValueError:
            continue
        if rel in files:
            return rel
    # index.* fallback for directory imports.
    for suffix in _JS_TS_SUFFIXES:
        candidate = target / f"index{suffix}"
        try:
            rel = _normalize_rel(str(candidate.relative_to(root)))
        except ValueError:
            continue
        if rel in files:
            return rel
    # Raw suffixed path (target already has an extension).
    if target.suffix in _JS_TS_SUFFIXES:
        try:
            rel = _normalize_rel(str(target.relative_to(root)))
        except ValueError:
            return None
        if rel in files:
            return rel
    return None


def _find_sinks(
    files: dict[str, Path], root: Path
) -> dict[str, list[tuple[str, int, str]]]:
    """rel_path -> list of (sink_kind, line_number, evidence_snippet)."""
    out: dict[str, list[tuple[str, int, str]]] = {}
    for rel, abs_path in files.items():
        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits: list[tuple[str, int, str]] = []
        for kind, pattern in _SINK_PATTERNS:
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                snippet = _line_snippet(content, match.start())
                hits.append((kind, line, snippet))
        if hits:
            out[rel] = hits
    return out


def _line_snippet(content: str, offset: int, radius: int = 80) -> str:
    start = max(0, content.rfind("\n", 0, offset) + 1)
    end = content.find("\n", offset)
    if end == -1:
        end = len(content)
    line = content[start:end].strip()
    if len(line) > radius * 2:
        line = line[: radius * 2] + "…"
    return line


def _walk_from_route(
    route: Route,
    route_file: str,
    graph: dict[str, set[str]],
    sinks_by_file: dict[str, list[tuple[str, int, str]]],
) -> list[TaintChain]:
    """BFS out from route_file, up to _MAX_HOPS. Emit chains at each sink."""
    visited: dict[str, int] = {route_file: 0}
    parents: dict[str, str] = {}
    queue: deque[str] = deque([route_file])
    chains: list[TaintChain] = []

    while queue and len(visited) < _MAX_FILES_VISITED_PER_ROUTE:
        current = queue.popleft()
        current_hops = visited[current]

        for kind, line, snippet in sinks_by_file.get(current, []):
            chains.append(
                TaintChain(
                    route_path=route.path,
                    route_method=route.method,
                    route_file=route_file,
                    sink_kind=kind,  # type: ignore[arg-type]
                    sink_file=current,
                    sink_line=line,
                    hops=current_hops,
                    files=_reconstruct_path(route_file, current, parents),
                    evidence_text=snippet,
                    confidence=_confidence_for_hops(current_hops),
                )
            )

        if current_hops >= _MAX_HOPS:
            continue
        for neighbor in graph.get(current, ()):  # noqa: SIM118
            if neighbor in visited:
                continue
            visited[neighbor] = current_hops + 1
            parents[neighbor] = current
            queue.append(neighbor)
    return chains


def _reconstruct_path(start: str, end: str, parents: dict[str, str]) -> list[str]:
    if start == end:
        return [start]
    chain: list[str] = [end]
    cursor = end
    while cursor in parents:
        cursor = parents[cursor]
        chain.append(cursor)
        if cursor == start:
            break
    chain.reverse()
    return chain


def _confidence_for_hops(hops: int) -> float:
    # Same-file sinks are already caught by the file-locality heuristic;
    # weight taint contribution slightly lower for 0-hop and taper further
    # for transitive edges — import != call.
    if hops == 0:
        return 0.65
    if hops == 1:
        return 0.60
    return 0.50
