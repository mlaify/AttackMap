"""Public, stable contract surface for AttackMap analyzers.

Anything you can import from ``attackmap.sdk`` is part of the stable analyzer
contract. Anything you cannot is an internal implementation detail of the
``attackmap`` package and may change without a major-version bump.

## What an analyzer is

An analyzer is a Python object that satisfies :class:`AnalyzerProtocol`:

- exposes ``metadata: AnalyzerMetadata``
- exposes a ``name`` property
- implements ``detect(root) -> bool`` — does this repo look like something
  the analyzer should run on?
- implements ``analyze(root) -> AnalyzerResult`` — extract structured
  signals (routes, external calls, hints, …) from the repo

External analyzers register themselves via the ``attackmap.analyzers``
Python entry-point group. See the README of any official analyzer (e.g.
``attackmap-analyzer-python``) for a working example.

## Responsibilities

Analyzers emit **structured signals** — small, evidence-bearing data points
with a file/line citation. They do *not* generate findings, attack paths,
or reports. Specifically:

| Owned by analyzers | Owned by core |
|---|---|
| Detecting whether they should run | Discovering and loading analyzers |
| Extracting routes, external calls, databases | Merging results across analyzers |
| Emitting auth/secret/service/edge/protocol/framework/entrypoint hints | Building the system graph |
| Surface-level normalization (path canonicalization, etc.) | Generating findings + severity |
| | Generating attack paths and threat-model output |
| | Rendering CLI / JSON / markdown reports |

If you find yourself wanting to add finding generation or report rendering
to an analyzer, the answer is almost always "emit a richer signal and let
core do the reasoning."

## Merge semantics

When multiple analyzers run against the same repo, their results are
merged by `attackmap.analyzers.merge_analyzer_results`. The schema is
declared in `attackmap.merge.MERGE_SCHEMA`; the rules are:

- **Order**: first-seen wins. Analyzers (built-in and plugin alike) run
  in ``(metadata.priority, name)`` order, so the lower priority value wins
  a duplicate signal.
- **Opt-in**: an analyzer with ``enabled_by_default=False`` runs only when
  selected with ``--module``; ``detect()`` still gates it.
- **Dedup**: each list field has a stable tuple key, e.g. routes are
  deduped by ``(path, method, file)`` and auth hints by ``(hint, file)``.
- **Route auth** (#256): a plugin that knows a route's guard sets
  ``Route.auth`` to ``"required"`` or ``"anonymous"`` (plus ``guards`` and
  ``guard_evidence``). Core trusts it over its own regex resolution and the
  ±40-line auth-hint window; ``"unknown"`` (the default) keeps the old
  behavior. On duplicate route keys a known state fills in an unknown one.
- **Languages**: union, sorted for stable display.
- **Files scanned**: summed.

Two analyzers that both emit a route for the same ``(path, method, file)``
produce one route in the merged result — whichever was emitted first.

## Contributing taint sinks (#240)

An analyzer can teach core's taint pass new sink signatures (a framework's
file-serving helper, an ORM's raw-query escape hatch) without touching core.
Register an entry point in the ``attackmap.taint_sinks`` group
(:data:`TAINT_SINK_PLUGIN_GROUP`) that resolves to a list of sink entries, a
callable returning one, or a path to a YAML file with a ``sinks:`` list::

    [project.entry-points."attackmap.taint_sinks"]
    myframework = "attackmap_analyzer_myframework.sinks:SINKS"

    SINKS = [
        {
            "id": "myframework-raw-sql",          # unique; prefix with your plugin
            "kind": "sql_execute",                # one of TAINT_SINK_KINDS
            "langs": ["python"],
            "regex": r"\\bRaw\\.sql\\s*\\(",
            "gate": "tainted",                    # or "any"
            "args": [0],                          # or "all" / "receiver" / "rest"
            "cwe": 89,                            # required
        },
    ]

Entries use the same schema as core's ``taint_sinks.yaml`` and must carry a
``cwe``. Check them in your tests with :func:`validate_taint_sink`; at scan
time an invalid entry is skipped with a warning instead of failing the scan.
Plugins reuse core's sink kinds (findings, CWE taxonomy and exploitability are
keyed on them) and core still decides reachability, flow and severity.

## Versioning

The names exported below are stable across minor releases of the
``attackmap`` package. Breaking changes to this surface only happen on
a major-version bump; deprecations get one release of overlap.
"""

from __future__ import annotations

from .contracts import (
    AnalyzerMetadata,
    AnalyzerProtocol,
    AnalyzerRepositoryModule,
    AnalyzerResult,
    normalize_analyzer_metadata,
)
from ..safe_fs import contained_file, is_contained, read_repo_text, walk_repo
from . import fs
from .fs import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, line_snippet, read_source, rel
from ..taint_sinks import PLUGIN_GROUP as TAINT_SINK_PLUGIN_GROUP
from ..taint_sinks import SINK_KINDS as TAINT_SINK_KINDS
from ..taint_sinks import validate_sink_entry as validate_taint_sink
from .models import (
    DEPENDENCY_ECOSYSTEMS,
    AuthHint,
    DatabaseHint,
    DependencyEcosystem,
    DependencyHint,
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

__all__ = [
    "AnalyzerResult",
    "AnalyzerMetadata",
    "AnalyzerRepositoryModule",
    "AnalyzerProtocol",
    "normalize_analyzer_metadata",
    "Route",
    "ExternalCall",
    "DatabaseHint",
    "AuthHint",
    "ServiceHint",
    "EdgeHint",
    "EntrypointHint",
    "ProtocolHint",
    "FrameworkHint",
    "SecretHint",
    "ScanResult",
    "DependencyHint",
    # Package ecosystems a DependencyHint may carry (#255).
    "DependencyEcosystem",
    "DEPENDENCY_ECOSYSTEMS",
    # Repo-confined filesystem helpers (#234): walk and read the scanned repo
    # without following symlinks out of it. Plugins should use these instead
    # of Path.rglob / read_text.
    "walk_repo",
    "is_contained",
    "contained_file",
    "read_repo_text",
    # Shared plugin walker/reader (#253): prunes by repo-relative dir name,
    # skips AttackMap output, caps size, never raises on unreadable files.
    "fs",
    "DEFAULT_SKIP_DIRS",
    "iter_repo_files",
    "read_source",
    "rel",
    "line_of",
    "line_snippet",
    # Plugin-contributed taint sinks (#240).
    "TAINT_SINK_PLUGIN_GROUP",
    "TAINT_SINK_KINDS",
    "validate_taint_sink",
]
