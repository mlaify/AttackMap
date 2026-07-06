"""Tests for the scan progress reporter (#36)."""

from __future__ import annotations

import io
from pathlib import Path

import json

from attackmap.progress import (
    PROGRESS_PROTOCOL_VERSION,
    JsonScanProgress,
    ScanProgress,
    _fmt_duration,
    _truncate,
    create_progress,
)
from attackmap.scanner import scan_repo


def _events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


class _FakeTTY(io.StringIO):
    """StringIO that claims to be a terminal so progress renders."""

    def isatty(self) -> bool:
        return True


def test_disabled_when_not_a_tty() -> None:
    stream = io.StringIO()  # plain StringIO → isatty() False
    p = ScanProgress(stream=stream)
    p.begin(10)
    p.advance("a.py")
    p.done("done")
    assert stream.getvalue() == ""


def test_disabled_when_explicitly_off() -> None:
    stream = _FakeTTY()
    p = ScanProgress(enabled=False, stream=stream)
    p.begin(10)
    p.advance("a.py")
    p.done()
    assert stream.getvalue() == ""


def test_renders_bar_and_percentage_on_tty() -> None:
    stream = _FakeTTY()
    p = ScanProgress(stream=stream)
    p.begin(4)
    for i in range(4):
        p.advance(f"file{i}.py")
    p.done("Scanned 4 files")
    out = stream.getvalue()
    assert "%" in out
    assert "ETA" in out
    assert "Scanned 4 files" in out


def test_stage_renders_and_stops_cleanly() -> None:
    stream = _FakeTTY()
    p = ScanProgress(stream=stream)
    p.begin(1)
    p.advance("x.py")
    p.stage("Taint / data-flow analysis")
    p.done()
    # spinner thread must be joined/stopped
    assert p._spin_thread is None


def test_fmt_duration() -> None:
    assert _fmt_duration(0) == "00:00"
    assert _fmt_duration(65) == "01:05"
    assert _fmt_duration(3725) == "1h02m"


def test_truncate_keeps_tail() -> None:
    assert _truncate("short.py", 32) == "short.py"
    long = "a/very/deeply/nested/path/to/module.py"
    out = _truncate(long, 20)
    assert out.startswith("…")
    assert out.endswith("module.py")
    assert len(out) == 20


def test_scan_repo_drives_progress_without_error(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def x(): return eval(request.args['e'])\n",
        encoding="utf-8",
    )
    stream = _FakeTTY()
    p = ScanProgress(stream=stream)
    scan = scan_repo(tmp_path, progress=p)
    assert scan.files_scanned == 1
    out = stream.getvalue()
    # per-file bar + at least one tail stage label rendered
    assert "Scanning files" in out
    assert "Taint" in out


def test_scan_repo_unaffected_without_progress(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    scan = scan_repo(tmp_path)  # no progress arg → old behavior
    assert scan.files_scanned == 1


# --- NDJSON progress sink (M0 for the macOS GUI) -------------------------


def test_json_progress_emits_ndjson_lifecycle() -> None:
    stream = io.StringIO()  # plain StringIO (not a TTY) — JSON sink emits anyway
    p = JsonScanProgress(stream=stream, min_interval=0.0)
    p.begin(3, label="Scanning files")
    p.advance("a.py")
    p.advance("b.py")
    p.advance("c.py")
    p.stage("Taint analysis")
    p.done("3 files, 1 finding")

    events = _events(stream)
    # Every line is valid JSON carrying the protocol version.
    assert all(e["v"] == PROGRESS_PROTOCOL_VERSION for e in events)
    kinds = [e["event"] for e in events]
    assert kinds[0] == "begin"
    assert kinds[-1] == "done"
    assert "stage" in kinds

    begin = events[0]
    assert begin["total"] == 3 and begin["label"] == "Scanning files"

    advances = [e for e in events if e["event"] == "advance"]
    assert [a["done"] for a in advances] == [1, 2, 3]
    assert advances[-1]["current"] == "c.py"

    done = events[-1]
    assert done["done"] == 3 and done["total"] == 3
    assert done["summary"] == "3 files, 1 finding"
    assert isinstance(done["elapsed_s"], (int, float)) and done["elapsed_s"] >= 0


def test_json_progress_throttles_but_keeps_count_accurate() -> None:
    stream = io.StringIO()
    # Large min_interval → intermediate advances are suppressed, but the final
    # file always emits and its count reflects every advance() call.
    p = JsonScanProgress(stream=stream, min_interval=1_000.0)
    p.begin(5)
    for name in ("a", "b", "c", "d", "e"):
        p.advance(name)
    p.done()

    advances = [e for e in _events(stream) if e["event"] == "advance"]
    assert len(advances) == 1  # only the final file survived the throttle
    assert advances[0]["done"] == 5 and advances[0]["total"] == 5


def test_json_progress_survives_closed_stream() -> None:
    stream = io.StringIO()
    p = JsonScanProgress(stream=stream, min_interval=0.0)
    p.begin(1)
    stream.close()  # simulate the GUI hanging up mid-scan
    p.advance("a.py")  # must not raise
    p.done("done")


def test_create_progress_selects_sink() -> None:
    tty = _FakeTTY()
    assert isinstance(create_progress("json", stream=io.StringIO()), JsonScanProgress)
    assert isinstance(create_progress("auto", stream=tty), ScanProgress)
    # 'none' and no_progress both yield a disabled no-op ScanProgress.
    off = create_progress("none", stream=tty)
    assert isinstance(off, ScanProgress)
    off.begin(3)
    off.advance("a.py")
    off.done()
    forced_off = create_progress("json", no_progress=True, stream=tty)
    assert isinstance(forced_off, ScanProgress)
    assert tty.getvalue() == ""  # nothing rendered by either disabled sink
