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

import os
import re

# Any path segment equal to one of these marks the file as test code.
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
