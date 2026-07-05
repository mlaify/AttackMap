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


def test_infra_routes_do_not_seed_taint(tmp_path: Path) -> None:
    """A static/infra endpoint (robots.txt, .well-known, health) must not seed
    a chain to a sink it merely shares a file with — #85 over-linking."""
    (tmp_path / "handler.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/robots.txt')\n"
        "def robots():\n"
        "    eval(request.args['x'])\n"
        "    return 'User-agent: *'\n"
        "@app.route('/xrpc/_health')\n"
        "def health():\n"
        "    eval(request.args['x'])\n"
        "    return 'ok'\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    return eval(request.args['q'])\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    routes = {c.route_path for c in scan.taint_chains}
    assert "/robots.txt" not in routes
    assert "/xrpc/_health" not in routes
    # a real application route in the same file still seeds normally
    assert "/search" in routes


def test_infra_route_opt_in_via_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ATTACKMAP_INCLUDE_INFRA_ROUTES", "1")
    (tmp_path / "h.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/healthz')\n"
        "def hz():\n"
        "    return eval(request.args['q'])\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(c.route_path == "/healthz" for c in scan.taint_chains)


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
        "def run(x): eval(x)\n", encoding="utf-8"
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/synthetic", method="POST", file="handler.py")],
    )
    chains = analyze_taint(scan, tmp_path)
    assert chains
    assert chains[0].sink_kind == "eval"
    assert chains[0].route_path == "/synthetic"


def test_static_local_deserialization_not_flagged(tmp_path: Path) -> None:
    """`yaml.load` of a static local file (shipped config at boot) is not an
    unsafe deserialization of untrusted data — must not seed a chain. This is
    the juice-shop `yaml.load(readFileSync('./swagger.yml'))` fan-out FP."""
    (tmp_path / "server.js").write_text(
        "const fs = require('fs')\n"
        "const yaml = require('js-yaml')\n"
        "const express = require('express')\n"
        "const app = express()\n"
        "const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))\n"
        "app.get('/status', (req, res) => res.json(swaggerDocument))\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert not [c for c in scan.taint_chains if c.sink_kind == "unsafe_deserialization"]


def test_dynamic_deserialization_still_flagged(tmp_path: Path) -> None:
    # request-derived bytes into yaml.load → real, still flagged.
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "import yaml\n"
        "app = Flask(__name__)\n"
        "@app.route('/load', methods=['POST'])\n"
        "def load():\n"
        "    return yaml.load(request.data)\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(c.sink_kind == "unsafe_deserialization" for c in scan.taint_chains)


def test_concatenated_path_deserialization_still_flagged(tmp_path: Path) -> None:
    # literal path + a variable (potential traversal) is NOT purely static.
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "import yaml\n"
        "app = Flask(__name__)\n"
        "@app.route('/hint/<key>')\n"
        "def hint(key):\n"
        "    return yaml.load(open('./data/' + key + '.yml').read())\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(c.sink_kind == "unsafe_deserialization" for c in scan.taint_chains)


def test_constant_eval_not_flagged_but_variable_eval_is(tmp_path: Path) -> None:
    # Separate files so hop-0 file-locality doesn't cross-link the routes.
    (tmp_path / "constant.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/const')\n"
        "def c():\n"
        "    return eval('1 + 1')\n",  # constant → benign, suppressed
        encoding="utf-8",
    )
    (tmp_path / "dynamic.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/dyn')\n"
        "def d():\n"
        "    return eval(request.args['x'])\n",  # variable → dangerous
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    eval_routes = {c.route_path for c in scan.taint_chains if c.sink_kind == "eval"}
    assert "/dyn" in eval_routes
    assert "/const" not in eval_routes


@pytest.mark.parametrize("sink_kind", ["eval", "exec", "subprocess_shell", "dynamic_open"])
def test_all_sink_kinds_are_detectable(tmp_path: Path, sink_kind: str) -> None:
    (tmp_path / "route.py").write_text(
        "from flask import Flask\nimport worker\napp=Flask(__name__)\n"
        "@app.route('/r')\ndef r(): return worker.go()\n",
        encoding="utf-8",
    )
    bodies = {
        # eval/exec use a variable arg (not a constant) — a constant eval is
        # benign and is now suppressed by the static-arg gate (see below).
        "eval": "def go(x): eval(x)\n",
        "exec": "def go(x): exec(x)\n",
        "subprocess_shell": "import subprocess\ndef go(): subprocess.run('ls', shell=True)\n",
        "dynamic_open": "def go(req): return open(req.path)\n",
    }
    (tmp_path / "worker.py").write_text(bodies[sink_kind], encoding="utf-8")
    scan = scan_repo(tmp_path)
    kinds = {c.sink_kind for c in scan.taint_chains}
    assert sink_kind in kinds
