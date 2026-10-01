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

# Quadratic backtracking is detected by *scaling*, not wall-clock alone, so
# slow CI runners don't make this flaky: a pattern fails when 4x the input
# costs >10x the time (linear ~4x, quadratic ~16x) and the large run is
# non-trivial in absolute terms.
SMALL, LARGE = 12_500, 50_000
MIN_SECONDS = 0.05
MAX_RATIO = 10.0
SHAPES = {
    "long_word": lambda n: "a" * n,
    "long_word_mixed": lambda n: "Ab1_" * (n // 4),
    "long_quote": lambda n: '"' + "A" * n,
    "long_space": lambda n: "x" + " " * n + "=",
    "nested_brackets": lambda n: "(" * (n // 2) + ")" * (n // 2),
    "dotted": lambda n: "a." * (n // 2),
    "dashes": lambda n: "a-" * (n // 2),
    "colons": lambda n: "a:" * (n // 2),
    "slashes": lambda n: "a/" * (n // 2),
    "equals_word": lambda n: ("a" * 1000 + "=") * (n // 1001),
    "url_like": lambda n: "https://" + "a" * n,
    "eyJ": lambda n: "eyJ" + "a" * n,
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


def _time(pattern: re.Pattern[str], payload: str) -> float:
    start = time.perf_counter()
    for _ in pattern.finditer(payload):
        pass
    return time.perf_counter() - start


@pytest.mark.parametrize("name,pattern", PATTERNS, ids=[n for n, _ in PATTERNS])
def test_pattern_scales_linearly(name: str, pattern: re.Pattern[str]) -> None:
    slow = []
    for label, make in SHAPES.items():
        large = _time(pattern, make(LARGE))
        if large < MIN_SECONDS:
            continue
        small = max(_time(pattern, make(SMALL)), 1e-4)
        if large / small > MAX_RATIO:
            slow.append(f"{label}: {small:.3f}s -> {large:.3f}s")
    assert not slow, f"{name} scales super-linearly on hostile input: {'; '.join(slow)}"
