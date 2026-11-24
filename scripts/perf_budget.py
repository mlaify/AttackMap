#!/usr/bin/env python3
"""Check the scan-time budget (#202) on the repos in evals/perf/budget.json.

    python scripts/realworld_corpus.py DEST evals/perf/budget.json
    python scripts/perf_budget.py DEST

Runs a core analysis of each repo (installed plugins included), prints the
wall-clock seconds per phase and fails if the total exceeds the case's
budget_seconds.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUDGET = ROOT / "evals" / "perf" / "budget.json"


def run(dest: Path) -> int:
    from attackmap.analyzers import analyze_repository
    from attackmap.progress import ScanProgress
    from attackmap.threat_model import generate_findings

    over = 0
    for case in json.loads(BUDGET.read_text(encoding="utf-8"))["cases"]:
        progress = ScanProgress(enabled=False)
        start = time.perf_counter()
        scan = analyze_repository(dest / case["path"], progress=progress)
        progress.stage("Findings")
        generate_findings(scan)
        progress.done()
        total = time.perf_counter() - start
        print(f"## {case['id']} ({scan.files_scanned} files): {total:.1f}s of {case['budget_seconds']}s")
        for phase, seconds in sorted(progress.timings.items(), key=lambda kv: -kv[1]):
            print(f"  {seconds:7.1f}s  {phase}")
        if total > case["budget_seconds"]:
            print(f"FAIL: {case['id']} over budget")
            over += 1
    return 1 if over else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(run(Path(sys.argv[1])))
