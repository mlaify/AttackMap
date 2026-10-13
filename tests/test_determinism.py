"""Scan output must not depend on the interpreter's string hash seed (#353, #369).

Set iteration order follows PYTHONHASHSEED. Where it decides what gets
analysed (a BFS under a visit cap) or what gets emitted (which root's path
names a transitive dependency), findings changed from run to run. Each
fixture is scanned in subprocesses under different seeds and the outputs
must match exactly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"

_SCAN = r"""
import json, sys
from attackmap.analyzer import identify_attack_surfaces
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings
scan = scan_repo(sys.argv[1])
print(json.dumps({
    "taint_chains": [c.model_dump(mode="json") for c in scan.taint_chains],
    "dependencies": [d.model_dump(mode="json") for d in scan.dependencies],
    "surfaces": [s.model_dump(mode="json") for s in identify_attack_surfaces(scan)],
    "findings": [f.model_dump(mode="json") for f in generate_findings(scan)],
}, sort_keys=True))
"""


def _scan_under_seed(root: Path, seed: int) -> dict:
    env = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": str(SRC)}
    out = subprocess.run(
        [sys.executable, "-c", _SCAN, str(root)],
        env=env, capture_output=True, text=True, check=True, timeout=120,
    )
    return json.loads(out.stdout)


def _fan_out_repo(root: Path) -> None:
    # The route imports 10 modules, each with a sink and 8 imports of its own.
    # The taint walk stops once it has discovered 40 files, after processing
    # about 4 of the 10, so which ones it reaches used to follow set order.
    mids = [f"mid_{i}_{'q' * i}" for i in range(10)]
    (root / "app.py").write_text(
        "from flask import Flask, request\n"
        + "".join(f"import {m}\n" for m in mids)
        + "app = Flask(__name__)\n\n"
        "@app.route('/run', methods=['POST'])\n"
        "def run():\n"
        "    data = request.get_data()\n"
        + "".join(f"    {m}.handle(data)\n" for m in mids)
        + "    return 'ok'\n",
        encoding="utf-8",
    )
    for m in mids:
        leaves = [f"{m}_leaf_{j}" for j in range(8)]
        (root / f"{m}.py").write_text(
            "import pickle\n"
            + "".join(f"import {leaf}\n" for leaf in leaves)
            + "\n\ndef handle(data):\n"
            + "".join(f"    {leaf}.handle(data)\n" for leaf in leaves)
            + "    return pickle.loads(data)\n",
            encoding="utf-8",
        )
        for leaf in leaves:
            (root / f"{leaf}.py").write_text("def handle(data):\n    return data\n", encoding="utf-8")
    # Two roots reach the same transitive package: the reported `via` path
    # used to depend on which root the BFS was seeded with first.
    (root / "uv.lock").write_text(
        'version = 1\n\n'
        '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [{ name = "alpha" }, { name = "beta" }, { name = "gamma" }]\n\n'
        '[[package]]\nname = "alpha"\nversion = "1.0.0"\ndependencies = [{ name = "shared" }]\n\n'
        '[[package]]\nname = "beta"\nversion = "1.0.0"\ndependencies = [{ name = "shared" }]\n\n'
        '[[package]]\nname = "gamma"\nversion = "1.0.0"\ndependencies = [{ name = "shared" }]\n\n'
        '[[package]]\nname = "shared"\nversion = "2.0.0"\n',
        encoding="utf-8",
    )


def test_scan_output_is_independent_of_the_hash_seed(tmp_path: Path) -> None:
    _fan_out_repo(tmp_path)
    runs = [_scan_under_seed(tmp_path, seed) for seed in (0, 1, 2, 3)]
    reached = {c["sink_file"] for c in runs[0]["taint_chains"]}
    assert 1 < len(reached) < 10, "the visit cap should cut the fan-out"
    assert any(d.get("via") for d in runs[0]["dependencies"]), "fixture should produce transitive paths"
    for other in runs[1:]:
        for key in runs[0]:
            assert other[key] == runs[0][key], key
