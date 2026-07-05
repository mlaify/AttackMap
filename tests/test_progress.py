"""Tests for the scan progress reporter (#36)."""

from __future__ import annotations

import io
from pathlib import Path

from attackmap.progress import ScanProgress, _fmt_duration, _truncate
from attackmap.scanner import scan_repo


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
