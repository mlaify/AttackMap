#!/usr/bin/env python3
"""Fetch the real-world precision corpus (evals/realworld/benchmark.json, #197).

Each case is cloned at its pinned tag into DEST/<path> and checked against the
pinned commit, so labels always refer to the same code. The repos are only
scanned, never built or run.

    python scripts/realworld_corpus.py DEST
    attackmap bench --benchmark evals/realworld/benchmark.json --root DEST
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "evals" / "realworld" / "benchmark.json"


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def fetch(dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    failed = 0
    for case in json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]:
        target = dest / case["path"]
        if not target.exists():
            _git("-c", "advice.detachedHead=false", "clone", "--quiet", "--depth", "1",
                 "--branch", case["ref"], case["repo"], str(target))
        head = _git("rev-parse", "HEAD", cwd=target)
        if head != case["commit"]:
            print(f"{case['id']}: {head} != pinned {case['commit']}", file=sys.stderr)
            failed += 1
        else:
            print(f"{case['id']}: {case['ref']} @ {head[:12]}")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(fetch(Path(sys.argv[1])))
