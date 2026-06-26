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

- **Order**: first-seen wins. Order across analyzers is the order
  `entry_points()` returns them in (Python's discovery order, by entry
  point name).
- **Dedup**: each list field has a stable tuple key, e.g. routes are
  deduped by ``(path, method, file)`` and auth hints by ``(hint, file)``.
- **Languages**: union, sorted for stable display.
- **Files scanned**: summed.

Two analyzers that both emit a route for the same ``(path, method, file)``
produce one route in the merged result — whichever was emitted first.

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
from .models import (
    AuthHint,
    DatabaseHint,
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
]
