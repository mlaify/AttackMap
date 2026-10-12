"""Hostile file sizes and shapes can't stall a scan (#236)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from attackmap.scanner import scan_repo
from attackmap.safe_fs import DEFAULT_MAX_FILE_BYTES, max_file_bytes


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n",
        encoding="utf-8",
    )
    return repo


def test_oversized_file_is_skipped_quickly_and_reported(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with (repo / "huge.py").open("w", encoding="utf-8") as fh:
        chunk = "x = 'A" + "A" * 1_000_000 + "'\n"
        for _ in range(50):  # ~50 MB
            fh.write(chunk)
    start = time.perf_counter()
    scan = scan_repo(repo)
    assert time.perf_counter() - start < 5
    assert any(lim.startswith("oversized file skipped") and lim.endswith("huge.py") for lim in scan.limitations)
    assert [r.path for r in scan.routes] == ["/ok"]


@pytest.mark.parametrize(
    "payload",
    [
        "x = " + "a" * 200_000 + "\n",  # one 200 KB word (the issue's hang)
        "router" + "_" * 200_000 + " = APIRouter(\n",
        "bp = Blueprint(" + "a" * 200_000 + "\n",
        "type Query {\n  " + "f" * 200_000 + "\n}\n",
    ],
    ids=["long_word", "router_assign", "blueprint", "graphql_field"],
)
def test_long_lines_under_the_cap_scan_in_linear_time(tmp_path: Path, payload: str) -> None:
    repo = _repo(tmp_path)
    (repo / "big.py").write_text(payload, encoding="utf-8")
    (repo / "schema.graphql").write_text(payload, encoding="utf-8")
    start = time.perf_counter()
    scan_repo(repo)
    assert time.perf_counter() - start < 5


def test_max_file_bytes_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert max_file_bytes() == DEFAULT_MAX_FILE_BYTES
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "10")
    assert max_file_bytes() == 10
    repo = _repo(tmp_path)
    scan = scan_repo(repo)
    assert scan.routes == []
    assert any("app.py" in lim for lim in scan.limitations)
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "not-a-number")
    assert max_file_bytes() == DEFAULT_MAX_FILE_BYTES


# Linearity is measured by scaling, not wall clock, so a slow runner can't
# fail it (it flaked at 10.7-11 s against a fixed 10 s bound on macOS): 8x the
# handlers must cost under MAX_RATIO x the small run. Linear is ~8-12x here
# (allocation and GC add a little). This catches a quadratic step that
# dominates the scan (a Python-level O(offset) loop per match measured 55x),
# but not a cheap one diluted by the linear work: #218's `content.count` line
# numbers run at C speed and only reach ~16x. The per-call tests below cover
# `line_number` and `_enclosing` directly.
_SMALL, _LARGE = 750, 6000
_MAX_RATIO = 20.0
_MIN_BASELINE = 0.05  # floor: below this the small run is mostly noise


def _handlers_repo(root: Path, count: int) -> tuple[Path, str]:
    chunk = (
        '@app.route("/r{i}")\ndef h{i}():\n'
        '    return requests.get("https://api{i}.example.com/x").text\n'
    )
    body = "from flask import Flask\nimport requests\napp = Flask(__name__)\n" + "".join(
        chunk.format(i=i) for i in range(count)
    )
    root.mkdir()
    (root / "app.py").write_text(body, encoding="utf-8")
    return root, body


def _scan_seconds(root: Path) -> float:
    start = time.perf_counter()
    scan_repo(root)
    return time.perf_counter() - start


def test_many_matches_in_a_large_file_scan_in_linear_time(tmp_path: Path) -> None:
    """#218: line numbers used to cost O(offset) per match (quadratic overall)."""
    small_repo, _ = _handlers_repo(tmp_path / "small", _SMALL)
    large_repo, body = _handlers_repo(tmp_path / "large", _LARGE)
    start = time.perf_counter()
    scan = scan_repo(large_repo)
    large = time.perf_counter() - start
    assert len(scan.routes) == _LARGE
    assert scan.routes[-1].line == body.count("\n", 0, body.index(f'"/r{_LARGE - 1}"')) + 1
    small = max(min(_scan_seconds(small_repo) for _ in range(3)), _MIN_BASELINE)
    if large / small > _MAX_RATIO:
        # One stalled sample shouldn't fail it: re-check on the best of three.
        large = min(large, _scan_seconds(large_repo), _scan_seconds(large_repo))
    assert large / small < _MAX_RATIO, f"{_SMALL} handlers: {small:.3f}s, {_LARGE}: {large:.3f}s"


def test_enclosing_function_is_the_innermost_one() -> None:
    """`_enclosing` climbs the nesting rather than scanning every function."""
    import random

    from attackmap.taint_flow import _PyFlow

    source = (
        "def a():\n"  # 1
        "    x = 1\n"  # 2
        "    def b():\n"  # 3
        "        y = 2\n"  # 4
        "        def c(): return 3\n"  # 5
        "        z = 4\n"  # 6
        "    w = 5\n"  # 7
        "\n"  # 8
        "@dec\n"  # 9
        "def d():\n"  # 10
        "    pass\n"  # 11
        "v = 6\n"  # 12
    )
    flow = _PyFlow(source)

    def name(line: int) -> str | None:
        node = flow._enclosing(line)
        return getattr(node, "name", None)

    assert [name(line) for line in range(1, 13)] == ["a", "a", "b", "b", "c", "b", "a", None, "d", "d", "d", None]

    # Matches the plain scan on random nestings.
    rng = random.Random(7)
    for _ in range(30):
        lines, depth = [], 0
        for i in range(rng.randint(1, 60)):
            depth = max(0, depth - rng.choice((0, 0, 1, 2)))
            lines.append("    " * depth + (f"def f{i}():" if rng.random() < 0.4 else "pass"))
            if lines[-1].endswith(":"):
                lines.append("    " * (depth + 1) + "pass")
                depth += 1
        flow = _PyFlow("\n".join(lines) + "\n")
        for line in range(1, len(lines) + 2):
            best, best_start = None, -1
            for start, end, node in flow.funcs:
                if start <= line <= end and start > best_start:
                    best, best_start = node, start
            assert flow._enclosing(line) is best, line



# Per-call complexity: the same number of lookups near the end of a file 4x
# larger must cost about the same (an O(offset) or O(functions) lookup costs
# ~4x). Timed as best of three, with the one-off index build done first.
_PER_CALL_MAX_RATIO = 2.0


def _per_call_ratio(make_lookup, small: int) -> float:
    def best(n: int) -> float:
        lookup = make_lookup(n)
        lookup()  # warm: build the per-file index outside the timing
        runs = []
        for _ in range(3):
            start = time.perf_counter()
            lookup()
            runs.append(time.perf_counter() - start)
        return max(min(runs), 1e-4)

    return best(4 * small) / best(small)


def test_line_number_lookup_does_not_scale_with_the_offset() -> None:
    """#218: `line_number` used `content.count("\\n", 0, offset)` per match."""
    from attackmap.srcpaths import line_number

    def make_lookup(lines: int):
        # A unique first line: `_line_starts` is cached by content, and an equal
        # but distinct string from an earlier run would be compared in full.
        content = f"# {time.perf_counter_ns()}\n" + "x = 1  # padding padding padding padding\n" * lines
        offsets = [len(content) - 1 - i * 7 for i in range(3000)]

        def lookup() -> None:
            for offset in offsets:
                line_number(content, offset)

        return lookup

    assert line_number("a\nb\nc", 4) == 3
    ratio = _per_call_ratio(make_lookup, 25_000)
    assert ratio < _PER_CALL_MAX_RATIO, ratio


def test_enclosing_lookup_does_not_scale_with_the_function_count() -> None:
    """Taint flow's `_enclosing` used to loop over every function per sink."""
    from attackmap.taint_flow import _PyFlow

    def make_lookup(functions: int):
        flow = _PyFlow("".join(f"def f{i}():\n    return {i}\n" for i in range(functions)))
        lines = [2 * functions - (i % 50) * 2 for i in range(3000)]

        def lookup() -> None:
            for line in lines:
                flow._enclosing(line)

        return lookup

    ratio = _per_call_ratio(make_lookup, 2_000)
    assert ratio < _PER_CALL_MAX_RATIO, ratio
