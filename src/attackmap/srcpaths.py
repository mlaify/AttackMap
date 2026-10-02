"""Source-path classification helpers (#67).

A single source of truth for "is this a test/spec file?", used to keep the
heuristic detection passes (taint, crypto, web-hardening, novel-vuln)
from flagging patterns that live in test scaffolding — a recurring
false-positive source on real repos (e.g. `salt = Math.random()` inside a
crypto package's own `*.test.ts`, or an `exec` in an integration test).

Set ``ATTACKMAP_INCLUDE_TESTS=1`` to opt back in (e.g. for supply-chain /
test-quality reviews where test code is in scope).
"""

from __future__ import annotations

import bisect
import functools
import os
import re

# Any path segment equal to one of these marks the file as test code.
# Every JavaScript/TypeScript source suffix the core scans (#227). Shared by
# the scanner, analyzers, taint, authz and fusion passes so none of them
# silently drops ES-module or CommonJS files.
JS_TS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})

_TEST_DIR_SEGMENTS = frozenset(
    {"tests", "test", "__tests__", "spec", "specs", "testing", "e2e", "__mocks__", "fixtures"}
)

# Filename shapes across ecosystems: foo.test.ts, foo.spec.js, foo_test.go,
# test_foo.py, foo_spec.rb, conftest.py, FooTest.java, FooTests.cs.
_TEST_FILE_RE = re.compile(
    r"""
    (?:\.(?:test|spec)\.[a-z0-9]+$)   # foo.test.ts / foo.spec.js
    | (?:_(?:test|spec)\.[a-z0-9]+$)  # foo_test.go / foo_spec.rb
    | (?:^test_[^/]*\.py$)            # test_foo.py
    | (?:^conftest\.py$)             # pytest conftest
    | (?:Tests?\.(?:java|kt|cs)$)     # FooTest.java / FooTests.cs
    """,
    re.IGNORECASE | re.VERBOSE,
)


def is_test_file(rel_path: str) -> bool:
    """Return True if ``rel_path`` looks like test/spec/fixture code.

    Honors ``ATTACKMAP_INCLUDE_TESTS`` — when set (to any non-empty
    value), nothing is treated as a test file, so the heuristic passes
    scan test code too.
    """
    if os.environ.get("ATTACKMAP_INCLUDE_TESTS"):
        return False
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    # Any parent directory named like a test dir.
    if any(segment.lower() in _TEST_DIR_SEGMENTS for segment in parts[:-1]):
        return True
    return _TEST_FILE_RE.search(parts[-1]) is not None


# Conventional infrastructure / static routes that don't run application logic
# on untrusted input: robots.txt, sitemap, favicon, `.well-known/*`, health /
# liveness / readiness probes, metrics, ping/version/status. A taint chain or
# exploitability score anchored on one of these is almost always import-walk
# over-linking (the handler returns static bytes and never touches the sink),
# so the detectors skip them. Central home so taint (#85) and exploitability
# (#79) share one definition.
_INFRA_ROUTE_RE = re.compile(
    r"""
    ^/?(?:
        robots\.txt$ | sitemap(?:\.xml)?$ | favicon\.ico$ | \.well-known(?:/|$)
      | (?:.*/)?_?health(?:z|check)?$ | (?:.*/)?livez$ | (?:.*/)?readyz$
      | metrics$ | ping$ | version$ | status$
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def is_infra_route(path: str) -> bool:
    """Return True if ``path`` is a conventional infra/static endpoint.

    Honors ``ATTACKMAP_INCLUDE_INFRA_ROUTES`` — set it to scan these anyway
    (e.g. auditing a health endpoint that really does hit a datastore)."""
    if os.environ.get("ATTACKMAP_INCLUDE_INFRA_ROUTES"):
        return False
    return _INFRA_ROUTE_RE.search(path) is not None


# Directory segments that hold third-party / vendored code the project doesn't
# maintain. Flagging weaknesses here is noise about someone else's dependency.
_VENDORED_DIR_SEGMENTS = frozenset(
    {
        "node_modules",
        "bower_components",
        "vendor",
        "vendored",
        "third_party",
        "third-party",
        "thirdparty",
        "external",
        "externals",
        "site-packages",
        "jspm_packages",
    }
)

# Minified / bundled build artifacts and generated TypeScript declaration
# stubs (`*.d.ts`) — not human-authored, executable source.
_MINIFIED_FILE_RE = re.compile(
    r"\.min\.(?:js|css|mjs|cjs)$|\.bundle\.js$|\.d\.ts$", re.IGNORECASE
)


def is_vendored_file(rel_path: str) -> bool:
    """Return True if ``rel_path`` is vendored third-party or minified/bundled
    code (e.g. ``UserInterface/External/three.js``, ``vendor/…``, ``*.min.js``).

    Honors ``ATTACKMAP_INCLUDE_VENDORED`` to scan it anyway (e.g. auditing a
    pinned/forked dependency)."""
    if os.environ.get("ATTACKMAP_INCLUDE_VENDORED"):
        return False
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    if any(segment.lower() in _VENDORED_DIR_SEGMENTS for segment in parts[:-1]):
        return True
    return _MINIFIED_FILE_RE.search(parts[-1]) is not None


__all__ = ["is_test_file", "is_infra_route", "is_vendored_file"]


# --- Locations cited in evidence text (#213, #214) ---------------------------
#
# Fallback for findings that don't carry structured `Finding.locations` (e.g.
# from third-party plugins): lift `file[:line]` out of evidence prose. One
# shared implementation for SARIF and suppression so the two can't drift.

_EXTENSIONLESS_FILES = frozenset(
    {"Dockerfile", "Containerfile", "Makefile", "Jenkinsfile", "Procfile", "Gemfile", "Rakefile", "Vagrantfile"}
)
_PATH_CHARS = r"[\w@()\[\]./\\+~-]"
# `src/app.py:12 — …` or `[src/app.py:12]`. The path starts at a token
# boundary and is matched possessively (`:` isn't a path char), so long
# bracket/paren runs stay linear (#236 regex budget).
_LEADING_LOC = re.compile(rf"(?<!{_PATH_CHARS})(?P<path>{_PATH_CHARS}++):(?P<line>\d+)\b")
# `… in src/app.py`, `… at lib/x.hpp:7`, `… in `Dockerfile``.
_PROSE_LOC = re.compile(rf"\b(?:in|at)\s+`?(?P<path>{_PATH_CHARS}++)`?(?::(?P<line>\d+))?")
_HAS_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,10}$")


def _clean_candidate(path: str) -> str | None:
    path = path.replace("\\", "/")
    # A leading bracket/paren that opens a `[file:line]` wrapper, not a
    # route-group segment like `(auth)/page.tsx`.
    while path[:1] in "[(" and path.count(path[0]) > path.count("]" if path[0] == "[" else ")"):
        path = path[1:]
    # Trailing sentence punctuation, and a closing paren/bracket that isn't
    # part of a balanced route-group segment like `(auth)`.
    while path and path[-1] in ".,;:":
        path = path[:-1]
    while path.endswith(")") and path.count("(") < path.count(")"):
        path = path[:-1]
    while path.endswith("]") and path.count("[") < path.count("]"):
        path = path[:-1]
    if not path or "://" in path or path.startswith(("/", "~")):
        return None
    name = path.rsplit("/", 1)[-1]
    if name in _EXTENSIONLESS_FILES or name.split(".", 1)[0] in _EXTENSIONLESS_FILES:
        return path
    if not _HAS_EXTENSION.search(name) or name.startswith("."):
        return path if name.startswith(".env") else None
    # Route paths (`/users/x`) start with `/` and were rejected above; a bare
    # dotted word like `v1.2` has no slash and a digit-only extension.
    if "/" not in path and re.search(r"\.\d+$", name):
        return None
    return path


def evidence_locations(evidence: list[str]) -> list[tuple[str, int | None]]:
    """Ordered, de-duplicated ``(file, line)`` pairs cited in evidence lines."""
    out: list[tuple[str, int | None]] = []
    seen: set[tuple[str, int | None]] = set()
    for text in evidence:
        positioned: list[tuple[int, str, int | None]] = []
        for match in _LEADING_LOC.finditer(text):
            path = _clean_candidate(match.group("path"))
            if path:
                positioned.append((match.start("path"), path, int(match.group("line"))))
        for match in _PROSE_LOC.finditer(text):
            path = _clean_candidate(match.group("path"))
            if path:
                line = match.group("line")
                positioned.append((match.start("path"), path, int(line) if line else None))
        # Text order, so the first cited location is the primary one.
        found = [(path, line) for _, path, line in sorted(positioned, key=lambda t: t[0])]
        for item in found:
            # Prefer the line-bearing form when the same file is cited both ways.
            if item[1] is None and any(f == item[0] and l is not None for f, l in found):
                continue
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


# --- Directories never scanned (#215) ----------------------------------------
#
# One set for every core walker. Matched against directory names *relative to
# the scanned root* — never against the absolute path, so a checkout that
# lives under e.g. /opt/atlassian/pipelines/agent/build is still scanned.
SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".attackmap",       # CLI cache / output dir
        ".attackmap-gui",   # the macOS GUI's report output dir
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".turbo",
        "out",
        "target",
        ".tox",
    }
)


def is_skipped_dir(name: str) -> bool:
    """`walk_repo(prune=...)` callback: never descend into these."""
    return name in SKIP_DIRS


def in_skipped_dir(rel: "str | os.PathLike[str]") -> bool:
    """True when a *repo-relative* file path sits under a skipped directory."""
    from pathlib import PurePath

    return any(part in SKIP_DIRS for part in PurePath(rel).parts[:-1])


# --- Offset -> line number (#218) ---------------------------------------------
#
# `content.count("\n", 0, offset)` is O(offset) per call; detectors call it once
# per match, which is O(n^2) on a large file with many matches (a 3 MB file took
# 34 s, 90% of it here). The line-start index is built once per file content
# and looked up by binary search.

@functools.lru_cache(maxsize=8)
def _line_starts(content: str) -> tuple[int, ...]:
    starts = [0]
    find = content.find
    pos = find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = find("\n", pos + 1)
    return tuple(starts)


def line_number(content: str, offset: int) -> int:
    """1-indexed line number of ``offset`` within ``content``."""
    if offset <= 0:
        return 1
    return bisect.bisect_right(_line_starts(content), offset)
