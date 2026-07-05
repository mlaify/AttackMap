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


__all__ = ["is_test_file"]
