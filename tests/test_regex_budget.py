"""Every module-level regex in attackmap stays linear-ish on hostile input (#236).

A scanned repo is untrusted: one long line must not make a pattern backtrack
quadratically and hang CI. This enumerates every compiled ``re.Pattern`` at
module level (including inside lists/tuples/dicts of patterns) and runs it
over adversarial payloads with a per-pattern time budget.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time

import pytest

import attackmap

BUDGET_SECONDS = 0.1
SIZE = 50_000
PAYLOADS = {
    "long_word": "a" * SIZE,
    "long_word_mixed": ("Ab1_" * (SIZE // 4)),
    "long_quote": '"' + "A" * SIZE,
    "long_space": "x" + " " * SIZE + "=",
    "nested_brackets": "(" * (SIZE // 2) + ")" * (SIZE // 2),
    "dotted": "a." * (SIZE // 2),
    "dashes": "a-" * (SIZE // 2),
    "colons": "a:" * (SIZE // 2),
    "slashes": "a/" * (SIZE // 2),
    "equals_word": ("a" * 1000 + "=") * (SIZE // 1001),
    "url_like": "https://" + "a" * SIZE,
    "eyJ": "eyJ" + "a" * SIZE,
}


def _collect(value, found, seen):
    if isinstance(value, re.Pattern):
        found.add(value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _collect(item, found, seen)
    elif isinstance(value, dict):
        for item in value.values():
            _collect(item, found, seen)


def _all_patterns() -> list[tuple[str, re.Pattern[str]]]:
    out: dict[re.Pattern[str], str] = {}
    for info in pkgutil.walk_packages(attackmap.__path__, "attackmap."):
        module = importlib.import_module(info.name)
        for attr, value in vars(module).items():
            found: set[re.Pattern[str]] = set()
            _collect(value, found, set())
            for pattern in found:
                if isinstance(pattern.pattern, str):
                    out.setdefault(pattern, f"{info.name}.{attr}")
    return sorted(((name, p) for p, name in out.items()), key=lambda t: t[0])


PATTERNS = _all_patterns()


def test_enumerates_a_meaningful_number_of_patterns() -> None:
    assert len(PATTERNS) > 150


@pytest.mark.parametrize("name,pattern", PATTERNS, ids=[n for n, _ in PATTERNS])
def test_pattern_within_budget(name: str, pattern: re.Pattern[str]) -> None:
    slow = []
    for label, payload in PAYLOADS.items():
        start = time.perf_counter()
        for _ in pattern.finditer(payload):
            if time.perf_counter() - start > BUDGET_SECONDS * 5:
                break
        elapsed = time.perf_counter() - start
        if elapsed > BUDGET_SECONDS:
            slow.append(f"{label}={elapsed:.2f}s")
    assert not slow, f"{name} backtracks on hostile input: {', '.join(slow)}"
