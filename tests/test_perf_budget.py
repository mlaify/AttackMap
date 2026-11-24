"""Scan-time budget plumbing (#202)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from attackmap.analyzers import analyze_repository
from attackmap.progress import ScanProgress

ROOT = Path(__file__).resolve().parents[1]


def test_phase_timings_are_recorded_without_a_tty(tmp_path: Path) -> None:
    progress = ScanProgress(enabled=False)
    progress.begin(1)
    time.sleep(0.01)
    progress.stage("Taint")
    progress.done()
    assert set(progress.timings) == {"Scanning files", "Taint"} and progress.timings["Scanning files"] >= 0.01

    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n    return 'x'\n")
    progress = ScanProgress(enabled=False)
    analyze_repository(tmp_path, progress=progress)
    assert {"Scanning files", "Taint / data-flow analysis", "Authorization (BOLA/IDOR)"} <= set(progress.timings)


def test_budget_cases_are_pinned_with_headroom() -> None:
    for case in json.loads((ROOT / "evals" / "perf" / "budget.json").read_text())["cases"]:
        assert len(case["commit"]) == 40 and case["repo"].startswith("https://"), case["id"]
        assert case["budget_seconds"] >= 2 * case["measured_seconds"], case["id"]
