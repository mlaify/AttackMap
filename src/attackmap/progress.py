"""Live scan progress with ETA (#36).

A repo scan can run for many minutes on a large tree, and a silent terminal
reads as "hung." This renders a single, self-updating status line to stderr:
a bar + percentage + count + ETA during the per-file pass, and an animated
spinner with elapsed time during the indeterminate tail analyzers (taint,
SBOM, authorization, anomalies) — the phase where a big monorepo spends most
of its time.

Zero third-party deps. TTY-aware: when stderr isn't a terminal (CI, piped to
a file) it stays silent so logs aren't polluted with carriage returns. The
scanner drives it through the small hook surface (`begin`/`advance`/`stage`/
`done`); when no progress object is passed, the scan runs exactly as before.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from typing import TextIO

# NDJSON progress protocol version (consumed by the macOS GUI and other
# non-TTY front-ends). Bump only on a breaking change to the event shape.
PROGRESS_PROTOCOL_VERSION = 1

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_BAR_WIDTH = 24
_MIN_REDRAW_INTERVAL = 0.08  # seconds — cap redraws so we don't thrash the TTY


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds >= 3600:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


class ScanProgress:
    """Render scan progress to a TTY. All methods are no-ops when disabled."""

    def __init__(self, *, enabled: bool = True, stream: TextIO | None = None) -> None:
        stream = stream if stream is not None else sys.stderr
        self._stream = stream
        self._enabled = enabled and hasattr(stream, "isatty") and stream.isatty()
        self._total = 0
        self._done = 0
        self._start = 0.0
        self._last_draw = 0.0
        self._last_len = 0
        self._label = ""
        # Spinner thread state for indeterminate stages.
        self._spin_stop: threading.Event | None = None
        self._spin_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # --- per-file phase ---------------------------------------------------

    def begin(self, total: int, label: str = "Scanning files") -> None:
        if not self._enabled:
            return
        self._stop_spinner()
        self._total = max(0, total)
        self._done = 0
        self._label = label
        self._start = time.monotonic()
        self._draw(force=True)

    def advance(self, current: str = "") -> None:
        if not self._enabled:
            return
        self._done += 1
        self._draw(current=current)

    # --- indeterminate tail phases ---------------------------------------

    def stage(self, label: str) -> None:
        """Switch to an indeterminate phase with an animated spinner."""
        if not self._enabled:
            return
        self._stop_spinner()
        self._label = label
        stop = threading.Event()
        self._spin_stop = stop
        started = time.monotonic()

        def _spin() -> None:
            i = 0
            while not stop.is_set():
                frame = _SPINNER[i % len(_SPINNER)]
                with self._lock:
                    self._write(f"{frame} {label}… ({_fmt_duration(time.monotonic() - started)})")
                i += 1
                stop.wait(0.12)

        thread = threading.Thread(target=_spin, daemon=True)
        self._spin_thread = thread
        thread.start()

    def done(self, summary: str = "") -> None:
        if not self._enabled:
            return
        self._stop_spinner()
        with self._lock:
            self._clear_line()
            if summary:
                self._stream.write(summary + "\n")
            self._stream.flush()

    # --- internals --------------------------------------------------------

    def _stop_spinner(self) -> None:
        if self._spin_stop is not None:
            self._spin_stop.set()
        if self._spin_thread is not None:
            self._spin_thread.join(timeout=0.5)
        self._spin_stop = None
        self._spin_thread = None

    def _draw(self, *, current: str = "", force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_draw) < _MIN_REDRAW_INTERVAL and self._done < self._total:
            return
        self._last_draw = now
        total = self._total or 1
        frac = min(1.0, self._done / total)
        filled = int(_BAR_WIDTH * frac)
        bar = "█" * filled + "░" * (_BAR_WIDTH - filled)
        elapsed = now - self._start
        eta = (elapsed / frac - elapsed) if frac > 0 else 0.0
        tail = f"  {_truncate(current, 32)}" if current else ""
        line = (
            f"{self._label}  [{bar}] {int(frac * 100):3d}%  "
            f"{self._done}/{self._total}  ETA {_fmt_duration(eta)}{tail}"
        )
        with self._lock:
            self._write(line)

    def _write(self, text: str) -> None:
        # Pad to erase any leftover from a previous longer line.
        pad = max(0, self._last_len - len(text))
        self._stream.write("\r" + text + " " * pad)
        self._stream.flush()
        self._last_len = len(text)

    def _clear_line(self) -> None:
        if self._last_len:
            self._stream.write("\r" + " " * self._last_len + "\r")
            self._last_len = 0


def _truncate(text: str, width: int) -> str:
    text = text.replace("\\", "/")
    if len(text) <= width:
        return text
    return "…" + text[-(width - 1):]


class JsonScanProgress:
    """Emit scan progress as newline-delimited JSON (one object per line).

    Same hook surface as ``ScanProgress`` (``begin``/``advance``/``stage``/
    ``done``) so the scanner drives either interchangeably. Unlike the TTY
    renderer this never gates on ``isatty`` — its whole purpose is to feed a
    non-terminal consumer (the macOS GUI) reading the child process's stderr.

    Event shapes (all carry ``"v": PROGRESS_PROTOCOL_VERSION``)::

        {"v":1,"event":"begin","total":1240,"label":"Scanning files"}
        {"v":1,"event":"advance","done":37,"total":1240,"current":"src/app.ts"}
        {"v":1,"event":"stage","label":"Taint analysis"}
        {"v":1,"event":"done","summary":"…","done":1240,"total":1240,"elapsed_s":92.4}

    ``advance`` events are throttled to at most one per ``min_interval`` seconds
    to keep the stream sane on large trees; ``done`` (per-file count) stays
    accurate because every advance still increments the internal counter and the
    latest count rides on each emitted event.
    """

    def __init__(self, *, stream: TextIO | None = None, min_interval: float = 0.1) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._min_interval = max(0.0, min_interval)
        self._total = 0
        self._done = 0
        self._start = 0.0
        self._last_emit = 0.0

    def begin(self, total: int, label: str = "Scanning files") -> None:
        self._total = max(0, total)
        self._done = 0
        self._start = time.monotonic()
        self._last_emit = self._start  # anchor throttle window to scan start
        self._emit("begin", total=self._total, label=label)

    def advance(self, current: str = "") -> None:
        self._done += 1
        now = time.monotonic()
        # Always emit the final file; throttle the rest.
        if self._done < self._total and (now - self._last_emit) < self._min_interval:
            return
        self._last_emit = now
        self._emit("advance", done=self._done, total=self._total, current=current)

    def stage(self, label: str) -> None:
        self._emit("stage", label=label)

    def done(self, summary: str = "") -> None:
        elapsed = round(time.monotonic() - self._start, 3) if self._start else 0.0
        self._emit(
            "done",
            summary=summary,
            done=self._done,
            total=self._total,
            elapsed_s=elapsed,
        )

    def _emit(self, event: str, **fields: object) -> None:
        payload = {"v": PROGRESS_PROTOCOL_VERSION, "event": event, **fields}
        try:
            self._stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._stream.flush()
        except (ValueError, OSError):
            # Never let a broken/closed pipe take down a scan.
            pass


def create_progress(
    fmt: str = "auto",
    *,
    no_progress: bool = False,
    stream: TextIO | None = None,
):
    """Build the right progress sink for ``--progress-format``.

    - ``none`` (or ``no_progress=True``) → a disabled ``ScanProgress`` no-op.
    - ``json`` → :class:`JsonScanProgress` (NDJSON, always emits).
    - ``auto`` / ``tty`` → :class:`ScanProgress` (TTY bar, self-silences when
      stderr isn't a terminal).
    """
    if no_progress or fmt == "none":
        return ScanProgress(enabled=False, stream=stream)
    if fmt == "json":
        return JsonScanProgress(stream=stream)
    return ScanProgress(enabled=True, stream=stream)


__all__ = [
    "ScanProgress",
    "JsonScanProgress",
    "create_progress",
    "PROGRESS_PROTOCOL_VERSION",
]
