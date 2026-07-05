"""Tests for the lite taint / import-graph analyzer (#45)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import Route, ScanResult, TaintChain
from attackmap.scanner import scan_repo
from attackmap.taint import analyze_taint
from attackmap.threat_model import generate_findings


FIXTURES = Path(__file__).parent / "fixtures"
PY_REPO = FIXTURES / "taint_repo"
JS_REPO = FIXTURES / "taint_js_repo"


# ---------------------------------------------------------------------------
# Python: route → service → db chain (2 hops)
# ---------------------------------------------------------------------------


def test_python_sql_execute_reached_via_two_hop_import_walk() -> None:
    scan = scan_repo(PY_REPO)
    matches = [
        c
        for c in scan.taint_chains
        if c.sink_kind == "sql_execute" and c.route_path == "/orders"
    ]
    assert matches, "expected a taint chain from /orders to db/orders.py"
    top = min(matches, key=lambda c: c.hops)
    assert top.hops == 2
    assert top.sink_file.endswith("db/orders.py")
    assert top.files[0].endswith("routes/orders.py")
    assert any(f.endswith("services/orders.py") for f in top.files)


def test_python_eval_sink_one_hop() -> None:
    scan = scan_repo(PY_REPO)
    matches = [c for c in scan.taint_chains if c.sink_kind == "eval" and c.route_path == "/calc"]
    assert matches
    assert matches[0].hops == 1
    assert matches[0].sink_file.endswith("services/calculator.py")


def test_python_subprocess_shell_sink_one_hop() -> None:
    scan = scan_repo(PY_REPO)
    matches = [
        c
        for c in scan.taint_chains
        if c.sink_kind == "subprocess_shell" and c.route_path == "/deploy"
    ]
    assert matches
    assert matches[0].hops == 1


def test_isolated_sink_not_reachable_from_any_route() -> None:
    """`isolated/lonely.py` has an eval() but no route imports it —
    the taint walker must not surface it as reachable."""
    scan = scan_repo(PY_REPO)
    for chain in scan.taint_chains:
        assert not chain.sink_file.endswith("isolated/lonely.py")


def test_hop_zero_when_route_and_sink_share_file(tmp_path: Path) -> None:
    handler = tmp_path / "handler.py"
    handler.write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x', methods=['POST'])\n"
        "def do():\n"
        "    body = request.get_json()\n"
        "    eval(body['expr'])\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    matches = [c for c in scan.taint_chains if c.sink_kind == "eval"]
    assert matches
    assert matches[0].hops == 0
    assert matches[0].files == [matches[0].route_file]


def test_max_hops_bounds_walk(tmp_path: Path) -> None:
    """Route → a → b → c chain; only sinks at hop ≤ 2 should surface."""
    (tmp_path / "route.py").write_text(
        "from flask import Flask\nimport a\napp=Flask(__name__)\n"
        "@app.route('/r')\ndef r(): return a.f()\n",
        encoding="utf-8",
    )
    (tmp_path / "a.py").write_text("import b\ndef f(): return b.g()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import c\ndef g(): return c.h()\n", encoding="utf-8")
    (tmp_path / "c.py").write_text(
        "def h():\n    cursor = None\n    cursor.execute('SELECT 1')\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    # c.py is 3 hops from route.py — beyond the limit.
    assert all(not c.sink_file.endswith("c.py") for c in scan.taint_chains)
    # b.py (2 hops) is still walked (no sink there); this test just guards
    # the depth limit — the important assertion is c.py is excluded.


# ---------------------------------------------------------------------------
# JavaScript / TypeScript: relative-import walk
# ---------------------------------------------------------------------------


def test_typescript_query_reached_via_two_hop_relative_imports() -> None:
    scan = scan_repo(JS_REPO)
    matches = [
        c
        for c in scan.taint_chains
        if c.sink_kind == "sql_execute" and c.route_path == "/orders"
    ]
    assert matches, "expected a taint chain through TS route/service/db"
    top = min(matches, key=lambda c: c.hops)
    assert top.hops == 2
    assert top.sink_file.endswith("db/orders.ts")


# ---------------------------------------------------------------------------
# Integration: scanner + threat_model consume taint chains
# ---------------------------------------------------------------------------


def test_scan_repo_populates_taint_chains_field() -> None:
    scan = scan_repo(PY_REPO)
    assert scan.taint_chains
    assert all(isinstance(c, TaintChain) for c in scan.taint_chains)


def test_taint_chain_source_analyzer_is_taint() -> None:
    scan = scan_repo(PY_REPO)
    assert scan.taint_chains
    assert all(c.source_analyzer == "taint" for c in scan.taint_chains)


def test_severe_taint_produces_finding_outside_framework_gate() -> None:
    """`/calc` → eval and `/deploy` → subprocess_shell are severe sinks;
    a finding should surface even though a Flask/services fixture may
    not clear the `_is_framework_mvc_scan` gate."""
    scan = scan_repo(PY_REPO)
    findings = generate_findings(scan)
    severe = [f for f in findings if "taint-chain" in f.tags]
    assert severe, "expected a severe-taint finding"
    # The fixture has an eval sink (/calc) and a subprocess sink (/deploy)
    # — both HIGH per the per-kind spec (#68).
    assert any(f.severity == "high" for f in severe)
    assert any("code execution via eval" in f.title for f in severe)


def test_analyze_taint_handles_empty_scan(tmp_path: Path) -> None:
    scan = ScanResult(root=str(tmp_path))
    assert analyze_taint(scan, tmp_path) == []


def test_analyze_taint_returns_empty_when_no_routes(tmp_path: Path) -> None:
    (tmp_path / "lib.py").write_text(
        "def q(): cursor.execute('SELECT 1')\n", encoding="utf-8"
    )
    scan = scan_repo(tmp_path)
    assert scan.routes == []
    assert scan.taint_chains == []


# ---------------------------------------------------------------------------
# Unit-level: analyze_taint respects an externally-populated route list
# ---------------------------------------------------------------------------


def test_analyze_taint_uses_scan_routes_directly(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "import worker\ndef h(): return worker.run()\n", encoding="utf-8"
    )
    (tmp_path / "worker.py").write_text(
        "def run(): eval('1+1')\n", encoding="utf-8"
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/synthetic", method="POST", file="handler.py")],
    )
    chains = analyze_taint(scan, tmp_path)
    assert chains
    assert chains[0].sink_kind == "eval"
    assert chains[0].route_path == "/synthetic"


@pytest.mark.parametrize("sink_kind", ["eval", "exec", "subprocess_shell", "dynamic_open"])
def test_all_sink_kinds_are_detectable(tmp_path: Path, sink_kind: str) -> None:
    (tmp_path / "route.py").write_text(
        "from flask import Flask\nimport worker\napp=Flask(__name__)\n"
        "@app.route('/r')\ndef r(): return worker.go()\n",
        encoding="utf-8",
    )
    bodies = {
        "eval": "def go(): eval('1+1')\n",
        "exec": "def go(): exec('a=1')\n",
        "subprocess_shell": "import subprocess\ndef go(): subprocess.run('ls', shell=True)\n",
        "dynamic_open": "def go(req): return open(req.path)\n",
    }
    (tmp_path / "worker.py").write_text(bodies[sink_kind], encoding="utf-8")
    scan = scan_repo(tmp_path)
    kinds = {c.sink_kind for c in scan.taint_chains}
    assert sink_kind in kinds
