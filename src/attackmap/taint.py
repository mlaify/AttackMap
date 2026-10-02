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

import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .safe_fs import is_contained, is_oversized, read_repo_text, walk_repo
from .models import Route, ScanResult, TaintChain, TaintFlowStep
from .srcpaths import JS_TS_SUFFIXES, is_infra_route, is_test_file, is_vendored_file, line_number
from .taint_flow import REST, FileFlow, SinkFlow
from .taint_sinks import SINKS, all_sinks
from .taint_sources import GO, JS, PHP, PY, lang_for_suffix

_MAX_HOPS = 2
# Bound the sweep so a deeply-linked monorepo can't blow up the scan.
_MAX_FILES_VISITED_PER_ROUTE = 40

# Recall mode (#148a). Aggressive discovery is only useful *behind* a verifier —
# so recall widens the walk, tags the extra reach speculative, and leaves
# adjudication to `--verify`/`--triage`. The default preset reproduces the
# conservative pass byte-for-byte; `recall_config()` is the aggressive preset.
_RECALL_MAX_HOPS = 4
_RECALL_MAX_FILES_VISITED_PER_ROUTE = 80


@dataclass(frozen=True)
class RecallConfig:
    """Knobs controlling how aggressively the taint walk discovers chains.

    Defaults == today's conservative pass. In the aggressive preset the extra
    reach (deeper hops, gates relaxed) is what makes a chain *speculative*: any
    chain past ``_MAX_HOPS`` or surfaced only because ``include_static_args``
    lifted the static-literal suppression is tagged so and confidence-docked.
    """

    max_hops: int = _MAX_HOPS
    max_files_visited: int = _MAX_FILES_VISITED_PER_ROUTE
    # Surface sinks whose argument looks like a static literal / local-file read
    # — the default pass suppresses these (#88 follow-up); recall keeps them as
    # speculative leads (provenance is a heuristic, not proof).
    include_static_args: bool = False
    # Capability-reach enumeration (#148b): surface *every* reach to a powerful
    # capability (network/template/fs/redirect) even with no known-bad pattern —
    # the bare call, not just the request-token-gated form. Recall-only,
    # speculative; the point is to list reaches a signature pass misses.
    capability_reach: bool = False

    @property
    def aggressive(self) -> bool:
        """True when any knob is widened past the conservative default."""
        return (
            self.max_hops > _MAX_HOPS
            or self.max_files_visited > _MAX_FILES_VISITED_PER_ROUTE
            or self.include_static_args
            or self.capability_reach
        )


DEFAULT_RECALL = RecallConfig()


def recall_config() -> RecallConfig:
    """The aggressive `--recall` preset."""
    return RecallConfig(
        max_hops=_RECALL_MAX_HOPS,
        max_files_visited=_RECALL_MAX_FILES_VISITED_PER_ROUTE,
        include_static_args=True,
        capability_reach=True,
    )

_PY_SUFFIXES = {".py"}
_JS_TS_SUFFIXES = JS_TS_SUFFIXES
_GO_SUFFIXES = {".go"}
_PHP_SUFFIXES = {".php"}
# Java (#239): indexed for same-file (0-hop) flows. Imports are not resolved,
# so a Java sink is only reached from a route in the same file.
_JAVA_SUFFIXES = {".java"}
# C# and Ruby (#240): indexed for same-file sinks only, like Java.
_SAME_FILE_ONLY_SUFFIXES = _JAVA_SUFFIXES | {".cs", ".rb"}
_SUPPORTED_SUFFIXES = _PY_SUFFIXES | _JS_TS_SUFFIXES | _GO_SUFFIXES | _PHP_SUFFIXES | _SAME_FILE_ONLY_SUFFIXES

# --- Import extraction -----------------------------------------------------

# Go imports: single `import "path"` and block `import ( "a"\n alias "b" )`.
# We only resolve INTRA-repo packages (those under the module path from go.mod).
_GO_IMPORT_RE = re.compile(r'\bimport\s+(?:"(?P<single>[^"]+)"|\((?P<block>[^)]*)\))', re.DOTALL)
_GO_IMPORT_PATH_RE = re.compile(r'"(?P<path>[^"]+)"')
_GO_MODULE_RE = re.compile(r"^\s*module\s+(?P<mod>\S+)", re.MULTILINE)


def _parse_go_imports(content: str) -> list[str]:
    """Return the import paths in a Go file (single and block form)."""
    paths: list[str] = []
    for match in _GO_IMPORT_RE.finditer(content):
        if match.group("single"):
            paths.append(match.group("single"))
        elif match.group("block") is not None:
            paths.extend(m.group("path") for m in _GO_IMPORT_PATH_RE.finditer(match.group("block")))
    return paths

# Only relative or bare-word imports we can resolve within the repo.
_JS_IMPORT_RE = re.compile(
    r"""(?:^|\s|;)                   # boundary
        (?:import\s+(?:[^"';]+?\s+from\s+)?|require\s*\(\s*)
        ["'](?P<path>[./][^"']+)["']
    """,
    re.VERBOSE,
)

# --- Call-graph awareness (#138) -------------------------------------------
# The import graph over-links: importing a module links a route to *every*
# sink in that module even when the imported symbol is never called. To
# approximate real call-edges we prune an import edge whose bound symbols are
# never *used* (called or referenced) in the importing file — a dead import no
# longer fans out to that module's sinks. This is recall-safe: an edge is only
# dropped when we have explicit binding names AND none appears outside its own
# import statement. Namespace/star/side-effect/dynamic imports carry no
# resolvable binding, so their edges are always kept (import-graph fallback).

# Import/require statements are stripped before collecting used identifiers so
# a symbol that appears *only* in its own import statement reads as unused. The
# patterns cover multi-line forms: parenthesized (`from x import (\n a,\n b\n)`)
# and backslash-continued (`from x import \` <nl> `a`) Python imports, and the
# `const { a } = require('…')` CommonJS binding declaration (whose left-hand side
# must be stripped too, else the binding always looks used).
_PY_IMPORT_LINE_RE = re.compile(
    r"""^[ \t]*(?:
            from\s+[\w.]+\s+import\s+(?:\*|\([^)]*\)|(?:\\\n|[^\n#])+)
          | import\s+(?:\\\n|[^\n#])+
        )""",
    re.MULTILINE | re.VERBOSE,
)
_JS_IMPORT_STMT_RE = re.compile(
    r"""import\s+[^;'"]*?\s+from\s+["'][^"']+["']       # import … from '…'
        | import\s+["'][^"']+["']                       # side-effect import '…'
        | (?:(?:const|let|var)\s+(?:\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*)?
          require\s*\(\s*["'][^"']+["']\s*\)             # [const … =] require('…')
    """,
    re.VERBOSE,
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _used_identifiers(content: str, suffix: str) -> set[str]:
    """Identifiers that appear in ``content`` outside of import statements —
    i.e. names that are actually referenced or called."""
    stripper = _PY_IMPORT_LINE_RE if suffix in _PY_SUFFIXES else _JS_IMPORT_STMT_RE
    body = stripper.sub(" ", content)
    return set(_IDENTIFIER_RE.findall(body))


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


_TAINTED_RE = re.compile(_TAINTED)


# Sink signatures live in the declarative registry `taint_sinks.yaml` (#240),
# loaded and validated by `taint_sinks`; plugins add entries through the
# `attackmap.taint_sinks` entry-point group. `SINKS` is the core table.
_SINK_PATTERNS = SINKS
_LEGACY_LANGS = frozenset({PY, JS, GO, PHP})


# --- Capability-reach patterns (#148b) -------------------------------------
# The bare-call forms of the request-token-gated sink kinds. The default pass
# only flags these when a request-shaped identifier is in the argument (a
# constant URL / template / path is fine); capability-reach surfaces the reach
# to the *capability itself* regardless — recall-only, speculative, deduped
# against any gated hit at the same line, and bounded to what a route reaches.
# NoSQL is deliberately omitted: a bare `.find(` is overwhelmingly JS array
# iteration, not a Mongo query, so without the request-token gate it's noise.
_CAPABILITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # network (SSRF surface)
    ("ssrf", re.compile(r"\brequests\.(?:get|post|put|delete|patch|head|request)\s*\(")),
    ("ssrf", re.compile(r"\bhttpx\.(?:get|post|put|delete|patch|head|request|Client)\s*\(")),
    ("ssrf", re.compile(r"\b(?:urlopen|urlretrieve)\s*\(")),
    (
        "ssrf",
        re.compile(
            r"\b(?:axios\s*\.\s*(?:get|post|put|delete|patch|head|request)|fetch|http\.(?:get|request))\s*\("
        ),
    ),
    # template rendering (SSTI surface)
    ("ssti", re.compile(r"\brender_template_string\s*\(")),
    ("ssti", re.compile(r"\bTemplate\s*\(")),
    # filesystem open (path-traversal surface)
    ("dynamic_open", re.compile(r"(?<![\w.])open\s*\(")),
    # redirect (open-redirect surface)
    ("open_redirect", re.compile(r"\bredirect\s*\(")),
    ("open_redirect", re.compile(r"\bres\s*\.\s*(?:redirect|location)\s*\(")),
)


# --- Sanitizer / validator awareness (#137, #239) ---------------------------
# Sanitizers are bound to the flow (#239): when the enclosing function can be
# analyzed, a neutralizer counts only if the tainted value passes through it
# (or a dominating guard checks it) on the way to the sink — see
# `taint_flow` and the catalog in `taint_sources`. This file-granular table is
# only the FALLBACK for sinks whose enclosing function can't be determined
# (module-level code, unparseable files): a sink-appropriate neutralizer
# anywhere in the file then marks the chain sanitized and downgrades it.
#
# Keep patterns HIGH-SIGNAL and sink-appropriate — a vague `validate(` would
# hide real bugs. `re.escape`/`html.escape` don't neutralize SSTI, and a bare
# `ipaddress.ip_address(` (often just logging) doesn't neutralize SSRF without
# an address-class decision, so neither counts (#239).
_SANITIZER_PATTERNS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "subprocess_shell": (
        ("shlex.quote", re.compile(r"\bshlex\.quote\s*\(")),
        ("pipes.quote", re.compile(r"\bpipes\.quote\s*\(")),
        ("escapeshellarg/escapeshellcmd", re.compile(r"\b(?:escapeshellarg|escapeshellcmd)\s*\(")),
    ),
    "sql_execute": (
        ("mysqli_real_escape_string", re.compile(r"\bmysqli_real_escape_string\s*\(")),
        ("pg_escape_*", re.compile(r"\bpg_escape_(?:string|literal|identifier)\s*\(")),
    ),
    "dynamic_open": (
        ("werkzeug.secure_filename", re.compile(r"\bsecure_filename\s*\(")),
        ("os.path.basename", re.compile(r"\bos\.path\.basename\s*\(")),
        ("path allow-list (realpath+startswith)", re.compile(r"\brealpath\s*\(")),
    ),
    "ssti": (
        ("markupsafe.escape", re.compile(r"\b(?:markupsafe|Markup)\.escape\s*\(|(?<![\w.])escape\s*\(")),
        ("bleach.clean", re.compile(r"\bbleach\.clean\s*\(")),
    ),
    "open_redirect": (
        ("is_safe_url", re.compile(r"\bis_safe_url\s*\(")),
        ("url_has_allowed_host_and_scheme", re.compile(r"\burl_has_allowed_host_and_scheme\s*\(")),
    ),
    "ssrf": (
        (
            "private/loopback/link-local address check",
            re.compile(r"\.is_(?:private|loopback|link_local|reserved)\b"),
        ),
        ("allow-list check", re.compile(r"\b(?:is_allowed_url|allowed_hosts|url_allowlist)\b")),
    ),
    "nosql_injection": (
        ("mongo-sanitize", re.compile(r"\b(?:mongoSanitize|mongo_sanitize|sanitize)\s*\(")),
    ),
}


def _find_sanitizer(kind: str, content: str) -> str | None:
    """Return a label for the first sink-appropriate neutralizer present in
    `content`, or None. File-granular — the fallback when no flow is known."""
    for label, pattern in _SANITIZER_PATTERNS.get(kind, ()):
        if pattern.search(content):
            return label
    return None


# --- Public API ------------------------------------------------------------


def analyze_taint(
    scan: ScanResult,
    root: str | Path | None = None,
    recall: RecallConfig = DEFAULT_RECALL,
) -> list[TaintChain]:
    """Walk the import graph from each route's file, emit TaintChains.

    ``scan.routes`` is treated as the source list. The walk is bounded by
    ``recall.max_hops`` and ``recall.max_files_visited``; duplicate
    (route, sink_file, sink_kind, sink_line) tuples are collapsed. Pass an
    aggressive ``recall`` (see ``recall_config()``) to widen discovery — the
    extra reach is tagged ``speculative`` on the returned chains (#148a).
    """
    root_path = Path(root or scan.root).resolve()
    if not root_path.exists():
        return []

    files = _index_repo(root_path)
    if not files:
        return []

    graph = _build_import_graph(files, root_path)
    sinks_by_file = _find_sinks(files, root_path, recall)

    # Route lines per file, so a same-file flow is attributed only to the
    # route whose handler encloses the sink (#239).
    route_lines: dict[str, list[int]] = {}
    for r in scan.routes:
        if r.line is not None:
            route_lines.setdefault(_normalize_rel(r.file), []).append(r.line)

    seen: set[tuple[str, str, str, int | None]] = set()
    chains: list[TaintChain] = []
    # Cache per-file content + name→module map so handler resolution reads
    # each route file at most once.
    content_cache: dict[str, str] = {}
    import_cache: dict[str, dict[str, str]] = {}

    for route in scan.routes:
        route_file = _normalize_rel(route.file)
        if route_file not in files:
            continue
        # Static / infra endpoints (robots.txt, .well-known, health) return
        # fixed bytes and don't feed request data to a sink — a chain from one
        # is import-walk over-linking, not a real flow (#85). Skip seeding them.
        if is_infra_route(route.path):
            continue

        # Handler-aware seeding (#107): for JS/TS central-registration apps,
        # seed from the module that DEFINES the route's handler rather than the
        # registration file — otherwise `server.ts` (importing ~100 handlers)
        # fans every route out to every imported sink. Falls back to the route
        # file when no handler identifier resolves (inline handlers, Python
        # decorators, etc.).
        seed_files = [route_file]
        if Path(route_file).suffix in _JS_TS_SUFFIXES:
            if route_file not in import_cache:
                try:
                    rf_content = files[route_file].read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    rf_content = ""
                content_cache[route_file] = rf_content
                import_cache[route_file] = _named_import_modules(
                    rf_content, route_file, files, root_path
                )
            handler_seeds = _handler_seed_files(
                route, content_cache.get(route_file, ""), import_cache[route_file]
            )
            if handler_seeds:
                seed_files = handler_seeds

        for seed in seed_files:
            for chain in _walk_from_route(
                route, seed, graph, sinks_by_file, recall, route_lines.get(route_file, [])
            ):
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
    skip_dirs = {
        ".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv",
        # Vendored third-party trees (#95) — import-walking someone else's
        # bundled library adds sinks the project doesn't own.
        "bower_components", "vendor", "third_party", "third-party",
        "external", "externals", "jspm_packages", "site-packages",
    }
    for path in walk_repo(root):
        if path.suffix not in _SUPPORTED_SUFFIXES or is_oversized(path):
            continue
        try:
            if any(part in skip_dirs for part in path.relative_to(root).parts):
                continue
        except ValueError:
            continue
        rel = _normalize_rel(str(path.relative_to(root)))
        # Skip test/spec files (#67) and vendored/minified/generated files
        # (#95, incl. `*.d.ts` type stubs) — sinks there are a large false-
        # positive source. `ATTACKMAP_INCLUDE_TESTS` / `_INCLUDE_VENDORED` opt in.
        if is_test_file(rel) or is_vendored_file(rel):
            continue
        out[rel] = path
    return out


def _normalize_rel(rel: str) -> str:
    return rel.replace("\\", "/")


def _go_module_path(root: Path) -> str | None:
    """The module path declared in go.mod, if present (e.g. github.com/x/y)."""
    gomod = root / "go.mod"
    try:
        if gomod.is_file() and is_contained(root, gomod):
            m = _GO_MODULE_RE.search(gomod.read_text(encoding="utf-8", errors="ignore"))
            if m:
                return m.group("mod")
    except OSError:
        pass
    return None


def _go_dir_index(files: dict[str, Path]) -> dict[str, set[str]]:
    """Map each directory (rel) to the set of .go files it contains — a Go
    package is a directory, so imports resolve to all files in the dir."""
    idx: dict[str, set[str]] = {}
    for rel in files:
        if rel.endswith(".go"):
            d = rel.rsplit("/", 1)[0] if "/" in rel else ""
            idx.setdefault(d, set()).add(rel)
    return idx


def _resolve_go_imports(
    content: str, module_path: str | None, dir_index: dict[str, set[str]]
) -> set[str]:
    """Resolve a Go file's intra-repo imports to the files in the imported
    package directories (module-path based)."""
    if not module_path:
        return set()
    out: set[str] = set()
    for imp in _parse_go_imports(content):
        if imp == module_path:
            pkgdir = ""
        elif imp.startswith(module_path + "/"):
            pkgdir = imp[len(module_path) + 1 :]
        else:
            continue  # external / stdlib package
        out |= dir_index.get(pkgdir, set())
    return out


_PHP_USE_RE = re.compile(r"^\s*use\s+(?P<fqcn>\\?[A-Za-z0-9_\\]+)", re.MULTILINE)
_PHP_REQUIRE_RE = re.compile(
    r"\b(?:require|include)(?:_once)?\s*\(?\s*['\"](?P<path>[^'\"]+)['\"]"
)


def _php_psr4_map(root: Path) -> dict[str, str]:
    """namespace-prefix → directory from composer.json PSR-4 autoload."""
    composer = root / "composer.json"
    out: dict[str, str] = {}
    try:
        data = json.loads(read_repo_text(root, composer, errors="ignore"))
    except (OSError, ValueError):
        return out
    for section in ("autoload", "autoload-dev"):
        psr4 = data.get(section, {}).get("psr-4", {}) if isinstance(data.get(section), dict) else {}
        for ns, directory in psr4.items():
            dirs = directory if isinstance(directory, list) else [directory]
            for d in dirs:
                out.setdefault(ns.rstrip("\\"), str(d).strip("/"))
    return out


def _resolve_php_imports(
    content: str, from_rel: str, files: dict[str, Path], root: Path, psr4: dict[str, str]
) -> set[str]:
    """Resolve PHP `use Ns\\Class` (via composer PSR-4) and `require '…'` to
    intra-repo files."""
    out: set[str] = set()
    for match in _PHP_USE_RE.finditer(content):
        fqcn = match.group("fqcn").lstrip("\\")
        for ns, directory in psr4.items():
            if fqcn == ns or fqcn.startswith(ns + "\\"):
                rest = fqcn[len(ns):].lstrip("\\").replace("\\", "/")
                rel = _normalize_rel(str((Path(directory) / (rest + ".php"))) if directory else rest + ".php")
                if rel in files:
                    out.add(rel)
                break
    from_dir = (root / from_rel).parent
    for match in _PHP_REQUIRE_RE.finditer(content):
        try:
            rel = _normalize_rel(str((from_dir / match.group("path")).resolve().relative_to(root)))
        except ValueError:
            continue
        if rel in files:
            out.add(rel)
    return out


def _build_import_graph(files: dict[str, Path], root: Path) -> dict[str, set[str]]:
    """rel_path -> set of rel_paths this file imports (intra-repo only).

    For Python and JS/TS, import edges are pruned to those whose bound symbols
    are actually used in the importing file (call-graph awareness, #138). Go
    and PHP keep the plain import-graph (no pruning) — their binding shapes are
    not resolved here, so every edge is kept as a fallback.
    """
    graph: dict[str, set[str]] = {rel: set() for rel in files}
    go_module = _go_module_path(root)
    go_dirs = _go_dir_index(files)
    php_psr4 = _php_psr4_map(root)
    for rel, abs_path in files.items():
        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if abs_path.suffix in _PY_SUFFIXES:
            edges = _resolve_py_imports_named(content, rel, files)
            graph[rel].update(_prune_unused_edges(edges, content, ".py"))
        elif abs_path.suffix in _GO_SUFFIXES:
            graph[rel].update(_resolve_go_imports(content, go_module, go_dirs))
        elif abs_path.suffix in _PHP_SUFFIXES:
            graph[rel].update(_resolve_php_imports(content, rel, files, root, php_psr4))
        elif abs_path.suffix in _SAME_FILE_ONLY_SUFFIXES:
            continue  # same-file flows only (#239, #240)
        else:  # JS/TS
            edges = _resolve_js_imports_named(content, rel, files, root)
            graph[rel].update(_prune_unused_edges(edges, content, ".js"))
    return graph


def _prune_unused_edges(
    edges: dict[str, set[str]], content: str, suffix: str
) -> set[str]:
    """Keep an edge unless it has explicit binding names none of which are used
    in ``content``. Edges with no resolvable bindings (empty set) are always
    kept — the import-graph fallback for namespace/star/side-effect imports."""
    used = _used_identifiers(content, suffix)
    kept: set[str] = set()
    for target, names in edges.items():
        if names and names.isdisjoint(used):
            continue  # dead import — no call/reference backs this edge (#138)
        kept.add(target)
    return kept


def _resolve_js_imports_named(
    content: str, from_rel: str, files: dict[str, Path], root: Path
) -> dict[str, set[str]]:
    """target rel -> bound names, for pruning. A target reached only through a
    side-effect / dynamic import (no named binding) maps to an empty set, which
    keeps its edge unconditionally."""
    edges: dict[str, set[str]] = {t: set() for t in _resolve_js_imports(content, from_rel, files, root)}
    for name, target in _named_import_modules(content, from_rel, files, root).items():
        edges.setdefault(target, set()).add(name)
    return edges


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


# from X import a, b as c  |  from X import (a,\n b)  |  from X import *
#   |  from X import \<nl> a   (parenthesized + backslash continuations)
_PY_FROM_IMPORT_RE = re.compile(
    r"^[ \t]*from\s+(?P<mod>[\w.]+)\s+import\s+(?P<names>\*|\([^)]*\)|(?:\\\n|[^\n#])+)",
    re.MULTILINE,
)
# import a, b.c as d
_PY_PLAIN_IMPORT_RE = re.compile(r"^[ \t]*import\s+(?P<mods>[\w., ]+)", re.MULTILINE)


def _resolve_py_imports_named(
    content: str, from_rel: str, files: dict[str, Path]
) -> dict[str, set[str]]:
    """target rel -> the binding names it introduces, for edge pruning (#138).

    A ``from X import *`` (unknown bindings) maps to an empty set, so its edge is
    always kept. Mirrors ``_resolve_py_imports`` for module resolution."""
    package_parts = Path(from_rel).parent.parts
    edges: dict[str, set[str]] = {}

    def _add(target: str | None, name: str | None) -> None:
        if target is None:
            return
        bucket = edges.setdefault(target, set())
        if name is not None:
            bucket.add(name)

    for match in _PY_FROM_IMPORT_RE.finditer(content):
        target = _resolve_py_module(match.group("mod"), package_parts, files)
        raw = match.group("names").strip()
        if raw == "*":
            _add(target, None)  # star import — keep edge unconditionally
            continue
        # Normalize multi-line forms: drop parens and backslash/newline
        # continuations so `(a,\n b)` and `\<nl> a` split cleanly.
        raw = raw.strip("()").replace("\\", " ").replace("\n", " ")
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            binding = part.split(" as ")[-1].strip()  # alias if present
            if binding.isidentifier():
                _add(target, binding)
    for match in _PY_PLAIN_IMPORT_RE.finditer(content):
        for item in match.group("mods").split(","):
            item = item.strip()
            if not item:
                continue
            if " as " in item:
                mod_part, binding = item.split(" as ", 1)
                binding = binding.strip()
            else:
                mod_part = item
                binding = item.split(".")[0].strip()  # `import a.b.c` binds `a`
            target = _resolve_py_module(mod_part.split(" as ")[0].split(".")[0], package_parts, files)
            if binding.isidentifier():
                _add(target, binding)
    return edges


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


# Named / default / namespace / require bindings → module specifier, so a
# route's handler identifier can be resolved to the module that defines it
# (#107 handler-aware seeding).
_JS_NAMED_IMPORT_RE = re.compile(r"""import\s+(?P<clause>[^;'"]+?)\s+from\s+["'](?P<path>[^"']+)["']""")
_JS_REQUIRE_BIND_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<clause>\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*["'](?P<path>[^"']+)["']\s*\)"""
)


def _binding_names(clause: str) -> list[str]:
    """Extract bound identifiers from an import/require clause.

    `{ a, b as c }` → [a, c]; `foo` → [foo]; `* as ns` → [ns];
    `Def, { a }` → [Def, a]."""
    names: list[str] = []
    clause = clause.strip()
    brace = re.search(r"\{([^}]*)\}", clause)
    if brace:
        for part in brace.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            name = re.split(r"\s+as\s+", part)[-1].strip()
            if name.isidentifier():
                names.append(name)
        before = clause[: brace.start()].strip().rstrip(",").strip()
        if before.isidentifier():
            names.append(before)
    else:
        ns = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
        if ns:
            names.append(ns.group(1))
        elif clause.isidentifier():
            names.append(clause)
    return names


def _named_import_modules(
    content: str, from_rel: str, files: dict[str, Path], root: Path
) -> dict[str, str]:
    """Map each imported binding name in ``content`` to its resolved intra-repo
    module (rel path). Only bindings that resolve to a file we indexed appear."""
    from_dir = (root / from_rel).parent
    out: dict[str, str] = {}
    for regex in (_JS_NAMED_IMPORT_RE, _JS_REQUIRE_BIND_RE):
        for match in regex.finditer(content):
            spec = match.group("path")
            if not spec.startswith((".", "/")):
                # Bare specifier (`require("path")`, `from "express"`) is a
                # package, never a sibling file that happens to share its name.
                continue
            rel = _resolve_js_target((from_dir / spec).resolve(), files, root)
            if rel is None:
                continue
            for name in _binding_names(match.group("clause")):
                out.setdefault(name, rel)
    return out


_ROUTE_CALL_RE = re.compile(
    r"\.(?:get|post|put|delete|patch|options|head|all|use)\s*\(", re.IGNORECASE
)


def _handler_seed_files(route: Route, content: str, name_to_module: dict[str, str]) -> list[str]:
    """For a JS/TS route registration (`app.get(path, …handler…)`), resolve an
    imported handler *identifier* to its defining module.

    Only the registration call's arguments are inspected — not the handler
    body. An inline handler (`=>` / `function`) keeps its own code in the
    registration file, so we don't redirect the seed (returns []); a reference
    to an imported handler (`getUserProfile`, `utils.asyncHandler(getUserProfile())`)
    seeds from that handler's module instead, avoiding the central-registration
    import-hub fan-out (#107)."""
    if route.line is None:
        return []
    lines = content.splitlines(keepends=True)
    idx = route.line - 1
    if idx < 0 or idx >= len(lines):
        return []
    line_start = sum(len(line) for line in lines[:idx])
    call = _ROUTE_CALL_RE.search(content, line_start, min(len(content), line_start + 400))
    if call is None:
        return []
    paren = content.find("(", call.start())
    if paren == -1:
        return []
    args = _extract_call_arg(content, paren)
    if "=>" in args or re.search(r"\bfunction\b", args):
        return []  # inline handler — its body lives in the registration file
    seeds: list[str] = []
    for ident in dict.fromkeys(re.findall(r"[A-Za-z_$][\w$]*", args)):
        mod = name_to_module.get(ident)
        if mod is not None and mod not in seeds:
            seeds.append(mod)
    return seeds


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


# Sink families that fire on reachability alone (no request-token gate),
# because the operation is dangerous regardless of the argument's shape.
# But that over-fires when the argument is provably STATIC/local — e.g.
# `yaml.load(fs.readFileSync('./swagger.yml'))` loads a shipped config at
# boot, not attacker bytes. Left ungated, one such call in a hub module
# fans out to a chain from every route (observed: 113/123 chains on a real
# app collapsing to one benign `yaml.load` of a static file). We suppress
# these kinds when the call argument is a bare string literal or a
# literal-path file read with no dynamic/attacker component.
_STATIC_GATED_KINDS = frozenset({"unsafe_deserialization", "eval", "exec"})

# A quoted string literal appears in the argument.
_ARG_STRING_LITERAL = re.compile(r"""['"][^'"]*['"]""")
# Signals the argument is (or may be) dynamic / attacker-influenced: string
# concatenation, template/f-string interpolation, a request / runtime-input
# container, or a `$`-variable (PHP `$_POST`/`$var`, so `unserialize($_POST['k'])`
# — whose `'k'` array-key literal would otherwise read as static — is flagged).
# If any appears, we do NOT treat the arg as static.
_ARG_DYNAMIC = re.compile(
    r"\+|\$|`|\b(?:req|request|body|query|params|payload|argv|input|stdin)\b|process\."
)


def _extract_call_arg(content: str, open_paren: int, cap: int = 400) -> str:
    """Return the text inside the balanced parens starting at ``open_paren``
    (the index of the ``(``), bounded to ``cap`` chars."""
    depth = 0
    end = min(len(content), open_paren + cap)
    for i in range(open_paren, end):
        ch = content[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return content[open_paren + 1 : i]
    return content[open_paren + 1 : end]


def _is_static_local_arg(content: str, match: re.Match[str]) -> bool:
    """True if the sink call's argument is provably static/local — a string
    literal or a literal-path file read — with no dynamic/attacker component."""
    paren = content.find("(", match.start())
    if paren == -1:
        return False
    arg = _extract_call_arg(content, paren)
    if not _ARG_STRING_LITERAL.search(arg):
        return False  # no literal → provenance unknown → keep flagging
    # Strip quoted spans before the dynamic check so a `+`/`${`/token that is
    # DATA inside a literal (e.g. `eval('1 + 1')`, `yaml.load('a: b+c')`)
    # doesn't read as concatenation/interpolation of the argument.
    residual = _ARG_STRING_LITERAL.sub("", arg)
    return _ARG_DYNAMIC.search(residual) is None


# Placeholder markers that indicate a parameterized query (bind params rather
# than string interpolation): %s / %(name)s, $1, :name, ?.
_SQL_PLACEHOLDER_RE = re.compile(r"%\(?\w*\)?[sd]|\$\d+|:[A-Za-z_]\w*|(?<!\w)\?(?!\w)")


def _is_parameterized_sql(content: str, match: re.Match[str], suffix: str = "") -> bool:
    """True if a `sql_execute` call is a *safe* parameterized query rather than a
    raw string-built one — so we don't flag it as an injection sink (#101)."""
    paren = content.find("(", match.start())
    if paren == -1:
        return False
    args = _extract_call_arg(content, paren)
    stripped = args.strip()
    if not stripped:
        return True  # builder terminal, e.g. Kysely `.execute()`
    if suffix == ".php":
        # PHP-tailored (#103): flag only on evidence of DYNAMIC query building —
        # `.` concatenation, double-quote `"…$var…"` interpolation, or sprintf.
        # Avoids the `+`/comma heuristic's traps here (`.` concat, mysqli's
        # ($conn, $sql) arg order). A bare `$db->query($sql)` is suppressed —
        # provenance is unknown and flagging every ORM call is noise.
        if re.search(r'["\']\s*\.|\.\s*\$|\bsprintf\s*\(', args) or re.search(r'"[^"]*\$', args):
            return False
        return True
    # Interpolation OUTSIDE string literals ⇒ raw/dynamic ⇒ NOT safe.
    if "${" in args or re.search(r"\bf['\"]", args):  # template literal / f-string
        return False
    no_str = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "", args)  # drop quoted spans
    # concat / .format() / %-format / Go fmt.Sprintf — string building, not binding.
    if re.search(r"\+|\.format\s*\(|%\s*[(\w]|\bSprintf\b|\bfmt\.", no_str):
        return False
    no_tmpl = re.sub(r"`[^`]*`", "", no_str)  # drop (now interp-free) template literals
    if "," in no_tmpl:
        return True  # query + params bind
    return _SQL_PLACEHOLDER_RE.search(args) is not None


@dataclass
class _SinkHit:
    kind: str
    line: int
    snippet: str
    # Neutralizer label: flow-bound when `flow` is known, else the file-level
    # fallback (#137).
    sanitizer: str | None
    # Recall only: kept because a gate was lifted (#148a/b) → speculative.
    relaxed: bool
    # Intra-procedural verdict for this call (#239); None when the enclosing
    # function couldn't be analyzed.
    flow: SinkFlow | None = None
    # The request gate was satisfied only by the traced flow (no same-call
    # request token) — such a hit belongs to the handler that encloses it.
    flow_only: bool = False


def _call_paren(content: str, match: re.Match[str]) -> int:
    """Offset of the sink call's opening paren: the one ending the match, the
    first inside it, or one right after it — else -1 (not a call)."""
    end = match.end()
    if end > match.start() and content[end - 1] == "(":
        return end - 1
    inside = content.find("(", match.start(), end)
    if inside != -1:
        return inside
    after = end
    while after < len(content) and content[after] in " \t":
        after += 1
    return after if after < len(content) and content[after] == "(" else -1


def _line_end(content: str, offset: int) -> int:
    end = content.find("\n", offset)
    return len(content) if end == -1 else end


def _find_sinks(
    files: dict[str, Path], root: Path, recall: RecallConfig = DEFAULT_RECALL
) -> dict[str, list[_SinkHit]]:
    """rel_path -> sink hits.

    Request-gated sinks fire on the legacy same-call request token or on an
    intra-procedural flow from a source into the dangerous argument (#239).
    Each hit carries that flow (source kind/line, steps) and a flow-bound
    sanitizer label; files whose functions can't be analyzed fall back to the
    file-granular sanitizer table. ``relaxed`` is True (recall only) when the
    hit was kept only because a gate was lifted — the static-literal
    suppression (#148a) or the request-token gate a capability-reach hit
    bypasses (#148b) — and the walk marks chains from such hits speculative.
    """
    out: dict[str, list[_SinkHit]] = {}
    for rel, abs_path in files.items():
        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        suffix = abs_path.suffix
        lang = lang_for_suffix(suffix)
        flows = FileFlow(content, suffix)  # parsed lazily, once per file
        hits: list[_SinkHit] = []
        # Fallback per-file sanitizer lookup, memoized per sink kind.
        sanitizer_by_kind: dict[str, str | None] = {}
        # (kind, line) already emitted by the gated pass — so a capability-reach
        # hit never duplicates a request-derived sink at the same spot.
        emitted: set[tuple[str, int]] = set()
        for sink in all_sinks():
            if lang not in sink.langs:
                continue
            if sink.requires is not None and sink.requires.search(content) is None:
                continue
            kind = sink.kind
            for match in sink.pattern.finditer(content):
                # A "dangerous-regardless" sink whose argument is a static
                # literal / local-file read (#88 follow-up): the default pass
                # suppresses it; recall keeps it as a speculative lead.
                relaxed = False
                if kind in _STATIC_GATED_KINDS and _is_static_local_arg(content, match):
                    if not recall.include_static_args:
                        continue
                    relaxed = True
                paren = _call_paren(content, match)
                # The call's argument text (or, for a statement sink, the rest
                # of the line) — what `when`/`unless` and the token gate read.
                if sink.args == REST or paren < 0:
                    arg_lo, arg_hi = match.end(), _line_end(content, match.end())
                    token_hi = arg_hi
                else:
                    arg_lo = paren + 1
                    arg_hi = arg_lo + len(_extract_call_arg(content, paren))
                    first_close = content.find(")", arg_lo)
                    token_hi = len(content) if first_close == -1 else first_close
                arg_text = content[arg_lo:arg_hi]
                if sink.when is not None and sink.when.search(arg_text) is None:
                    continue
                if sink.unless is not None and sink.unless.search(arg_text) is not None:
                    continue
                snippet = _line_snippet(content, match.start())
                flow = flows.sink_flow(kind, paren, sink.args, snippet, match.start(), match.end())
                traced = flow is not None and (flow.tainted or flow.sanitized)
                flow_only = False
                if sink.gate == "tainted":
                    # The pre-#239 same-call gate: a request-container token
                    # between the call's paren and its first `)`.
                    legacy_ok = sink.token_gate and _TAINTED_RE.search(content, arg_lo, token_hi) is not None
                    if not legacy_ok:
                        if not traced:
                            continue
                        flow_only = True
                # Suppress parameterized SQL — bind params / builder / placeholders
                # only — vs. raw string-built queries (#101). A traced flow into the
                # query argument itself overrides it: `$db->query($sql)` with a
                # request-built `$sql` is injectable whatever the call looks like.
                if kind == "sql_execute" and not traced and _is_parameterized_sql(content, match, suffix):
                    continue
                if flow is not None:
                    sanitizer = flow.sanitizer if flow.sanitized else None
                else:
                    if kind not in sanitizer_by_kind:
                        sanitizer_by_kind[kind] = _find_sanitizer(kind, content)
                    sanitizer = sanitizer_by_kind[kind]
                line = line_number(content, match.start())
                hits.append(_SinkHit(kind, line, snippet, sanitizer, relaxed, flow, flow_only))
                emitted.add((kind, line))

        # Capability-reach pass (#148b, recall only): the bare-call form of the
        # request-gated kinds, surfaced even without a request token. Always
        # relaxed → speculative; skipped where the gated pass already fired.
        # These carry NO sanitizer label: sanitizer status describes a tainted
        # flow being neutralized, but a capability-reach hit asserts no taint —
        # a file-level sanitizer token must not mark it sanitized (which would
        # make generate_findings drop it and silently lose the capability
        # inventory this pass exists to produce).
        if recall.capability_reach and lang in _LEGACY_LANGS:
            for kind, pattern in _CAPABILITY_PATTERNS:
                for match in pattern.finditer(content):
                    line = line_number(content, match.start())
                    if (kind, line) in emitted:
                        continue
                    snippet = _line_snippet(content, match.start())
                    hits.append(_SinkHit(kind, line, snippet, None, True))
                    emitted.add((kind, line))
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
    sinks_by_file: dict[str, list[_SinkHit]],
    recall: RecallConfig = DEFAULT_RECALL,
    route_lines: list[int] | None = None,
) -> list[TaintChain]:
    """BFS out from route_file, up to ``recall.max_hops``. Emit chains at each
    sink; tag as speculative any chain that only exists because a recall knob
    was widened — a relaxed-gate sink, or a sink in a file the *conservative*
    traversal (default hop depth + visit budget) would never have processed
    (#148a). Comparing against the default-reachable set covers both the deeper
    hops and the widened visit cap precisely — a fan-out-heavy graph can push a
    within-two-hops sink past the 40-file budget, and that reach is speculative
    too.

    Same-file flows are attributed to the route whose handler encloses the
    sink (#239): when the sink sits in *another* route's handler, this route
    gets no flow (and no chain at all if the flow was the only gate)."""
    # The set of files the conservative pass would actually process — computed
    # only when a knob is widened (otherwise nothing is speculative and the
    # traversals are identical).
    default_reachable: set[str] | None = (
        _reachable_files(route_file, graph, _MAX_HOPS, _MAX_FILES_VISITED_PER_ROUTE)
        if recall.aggressive
        else None
    )
    route_lines = route_lines or []

    visited: dict[str, int] = {route_file: 0}
    parents: dict[str, str] = {}
    queue: deque[str] = deque([route_file])
    chains: list[TaintChain] = []

    while queue and len(visited) < recall.max_files_visited:
        current = queue.popleft()
        current_hops = visited[current]

        for hit in sinks_by_file.get(current, []):
            flow = hit.flow
            if current_hops == 0 and flow is not None and flow.span is not None:
                lo, hi = flow.span
                in_handler = route.line is None or lo <= route.line <= hi
                other_handler = any(lo <= ln <= hi for ln in route_lines if ln != route.line)
                if not in_handler and other_handler:
                    if hit.flow_only:
                        continue  # another route's input, not this one's
                    flow = None
            confidence = _confidence_for_hops(current_hops)
            if flow is not None and flow.tainted:
                # A traced source→sink flow is stronger evidence than reach.
                confidence = round(min(0.9, confidence + 0.15), 2)
            if hit.sanitizer is not None:
                # A neutralizer is present at the sink — likely defended.
                # Downgrade well below the HIGH threshold, keep as evidence.
                confidence = round(confidence * 0.4, 2)
            # A relaxed-gate hit, or a sink the conservative pass would never
            # have reached, is a discovery lead — mark it and dock confidence so
            # it can't clear the HIGH bar until the verifier confirms it.
            speculative = hit.relaxed or (
                default_reachable is not None and current not in default_reachable
            )
            if speculative:
                confidence = round(confidence * 0.5, 2)
            traced = flow is not None and (flow.tainted or flow.sanitized)
            chains.append(
                TaintChain(
                    route_path=route.path,
                    route_method=route.method,
                    route_file=route_file,
                    sink_kind=hit.kind,  # type: ignore[arg-type]
                    sink_file=current,
                    sink_line=hit.line,
                    hops=current_hops,
                    files=_reconstruct_path(route_file, current, parents),
                    evidence_text=hit.snippet,
                    confidence=confidence,
                    sanitized=hit.sanitizer is not None,
                    sanitizer_evidence=hit.sanitizer,
                    speculative=speculative,
                    source_kind=flow.source_kind if traced and flow is not None else None,
                    source_line=flow.source_line if traced and flow is not None else None,
                    flow=(
                        [
                            TaintFlowStep(file=current, line=ln, kind=k, evidence_text=note)  # type: ignore[arg-type]
                            for ln, k, note in flow.steps
                        ]
                        if traced and flow is not None
                        else []
                    ),
                )
            )

        if current_hops >= recall.max_hops:
            continue
        for neighbor in graph.get(current, ()):  # noqa: SIM118
            if neighbor in visited:
                continue
            visited[neighbor] = current_hops + 1
            parents[neighbor] = current
            queue.append(neighbor)
    return chains


def _reachable_files(
    start: str, graph: dict[str, set[str]], max_hops: int, max_files: int
) -> set[str]:
    """The set of files a BFS bounded by ``max_hops`` / ``max_files`` would
    *process* (pop) from ``start``. Mirrors ``_walk_from_route``'s control flow
    exactly so it is a faithful model of what the conservative pass reaches —
    used to decide which recall discoveries are speculative (#148a)."""
    visited: dict[str, int] = {start: 0}
    queue: deque[str] = deque([start])
    processed: set[str] = set()
    while queue and len(visited) < max_files:
        current = queue.popleft()
        processed.add(current)
        if visited[current] >= max_hops:
            continue
        for neighbor in graph.get(current, ()):  # noqa: SIM118
            if neighbor in visited:
                continue
            visited[neighbor] = visited[current] + 1
            queue.append(neighbor)
    return processed


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
