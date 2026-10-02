"""Intra-procedural def-use taint propagation (#239).

Fixtures under ``tests/fixtures/taint_flow/<lang>/`` carry the two-line
source→variable→sink shape for SSRF, SQLi, path traversal and command
execution, plus a ``*_sanitized`` twin per case with a flow-bound sanitizer or
dominating guard. Each source / sink line is marked ``taint: source`` /
``taint: sink`` so the expected lines are read from the file, not hard-coded.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from attackmap.models import Route, ScanResult, TaintChain
from attackmap.sarif import build_sarif
from attackmap.scanner import scan_repo
from attackmap.taint import analyze_taint
from attackmap.threat_model import generate_findings

FIX = Path(__file__).parent / "fixtures" / "taint_flow"
REPO_ROOT = Path(__file__).resolve().parents[1]

# (lang dir, file, sink kind, method, route)
VULNERABLE = [
    ("py", "ssrf.py", "ssrf", "GET", "/fetch"),
    ("py", "sqli.py", "sql_execute", "GET", "/orders/search"),
    ("py", "path.py", "dynamic_open", "GET", "/reports/download"),
    ("py", "cmd.py", "subprocess_shell", "POST", "/diag/ping"),
    ("js", "ssrf.js", "ssrf", "GET", "/fetch"),
    ("js", "sqli.js", "sql_execute", "GET", "/orders/search"),
    ("js", "path.js", "dynamic_open", "GET", "/reports/download"),
    ("js", "cmd.js", "subprocess_shell", "POST", "/diag/ping"),
    ("go", "ssrf.go", "ssrf", "GET", "/fetch"),
    ("go", "sqli.go", "sql_execute", "GET", "/orders/search"),
    ("go", "path.go", "dynamic_open", "GET", "/reports/download"),
    ("go", "cmd.go", "subprocess_shell", "POST", "/diag/ping"),
    ("php", "ssrf.php", "ssrf", "GET", "/fetch"),
    ("php", "sqli.php", "sql_execute", "GET", "/orders/search"),
    ("php", "path.php", "dynamic_open", "GET", "/reports/download"),
    ("php", "cmd.php", "subprocess_shell", "POST", "/diag/ping"),
    ("java", "FetchController.java", "ssrf", "GET", "/fetch"),
    ("java", "OrderSearchController.java", "sql_execute", "GET", "/orders/search"),
    ("java", "ReportController.java", "dynamic_open", "GET", "/reports/download"),
    ("java", "PingController.java", "subprocess_shell", "POST", "/diag/ping"),
]

SANITIZED = [
    ("py", "ssrf_sanitized.py", "ssrf", "GET", "/fetch", "private/loopback/link-local address check"),
    ("py", "sqli_sanitized.py", "sql_execute", "GET", "/orders/lookup", "int() cast"),
    ("py", "path_sanitized.py", "dynamic_open", "GET", "/reports/download", "werkzeug.secure_filename"),
    ("py", "cmd_sanitized.py", "subprocess_shell", "POST", "/diag/ping", "shlex.quote"),
    ("js", "ssrf_sanitized.js", "ssrf", "GET", "/fetch", "allow-list check"),
    ("js", "sqli_sanitized.js", "sql_execute", "GET", "/orders/:id", "parseInt/Number cast"),
    ("js", "path_sanitized.js", "dynamic_open", "GET", "/reports/download", "path.basename"),
    ("js", "cmd_sanitized.js", "subprocess_shell", "POST", "/diag/ping", "allow-list check"),
    ("go", "ssrf_sanitized.go", "ssrf", "GET", "/fetch", "allow-list check"),
    ("go", "sqli_sanitized.go", "sql_execute", "GET", "/orders/lookup", "strconv cast"),
    ("go", "path_sanitized.go", "dynamic_open", "GET", "/reports/download", "filepath.Base"),
    ("go", "cmd_sanitized.go", "subprocess_shell", "POST", "/diag/ping", "regex validation"),
    ("php", "ssrf_sanitized.php", "ssrf", "GET", "/fetch", "allow-list check"),
    ("php", "sqli_sanitized.php", "sql_execute", "GET", "/orders/lookup", "intval cast"),
    ("php", "path_sanitized.php", "dynamic_open", "GET", "/reports/download", "basename()"),
    ("php", "cmd_sanitized.php", "subprocess_shell", "POST", "/diag/ping", "escapeshellarg/escapeshellcmd"),
    ("java", "FetchSanitizedController.java", "ssrf", "GET", "/fetch", "allow-list check"),
    ("java", "OrderLookupController.java", "sql_execute", "GET", "/orders/lookup", "Java numeric parse"),
    ("java", "ReportSanitizedController.java", "dynamic_open", "GET", "/reports/download", "FilenameUtils.getName"),
    ("java", "PingSanitizedController.java", "subprocess_shell", "POST", "/diag/ping", "regex validation"),
]


def _marker(path: Path, marker: str) -> int:
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if f"taint: {marker}" in line:
            return i
    raise AssertionError(f"no '{marker}' marker in {path}")


def _route_line(path: Path, route: str) -> int:
    """The line registering/declaring the route (decorator, mapping, comment)."""
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if route in line:
            return i
    raise AssertionError(f"route {route} not found in {path}")


def _chains(lang: str, name: str, method: str, route: str) -> list[TaintChain]:
    root = FIX / lang
    scan = ScanResult(
        root=str(root),
        routes=[Route(path=route, method=method, file=name, line=_route_line(root / name, route))],
    )
    return analyze_taint(scan, root)


def _at_sink(chains: list[TaintChain], kind: str, line: int) -> TaintChain:
    hits = [c for c in chains if c.sink_kind == kind and c.sink_line == line]
    assert hits, f"no {kind} chain at line {line}: {[(c.sink_kind, c.sink_line) for c in chains]}"
    return hits[0]


# ---------------------------------------------------------------------------
# Acceptance: two-line source→var→sink detected, with source_line
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lang,name,kind,method,route", VULNERABLE, ids=[f"{c[0]}-{c[1]}" for c in VULNERABLE])
def test_two_line_flow_is_detected_with_source_line(lang, name, kind, method, route) -> None:
    path = FIX / lang / name
    chain = _at_sink(_chains(lang, name, method, route), kind, _marker(path, "sink"))
    assert chain.source_line == _marker(path, "source")
    assert chain.source_kind in {"query", "body", "path_param", "header", "cookie"}
    assert chain.sanitized is False
    assert chain.flow[0].kind == "source" and chain.flow[0].line == chain.source_line
    assert chain.flow[-1].kind == "sink" and chain.flow[-1].line == chain.sink_line
    assert all(step.file == name for step in chain.flow)


@pytest.mark.parametrize(
    "lang,name,kind,method,route,label", SANITIZED, ids=[f"{c[0]}-{c[1]}" for c in SANITIZED]
)
def test_flow_bound_sanitizer_marks_chain_sanitized(lang, name, kind, method, route, label) -> None:
    path = FIX / lang / name
    chains = _chains(lang, name, method, route)
    chain = _at_sink(chains, kind, _marker(path, "sink"))
    assert chain.sanitized is True
    assert chain.sanitizer_evidence == label
    assert chain.source_line == _marker(path, "source")
    assert any(step.kind in {"sanitizer", "guard"} for step in chain.flow)
    # Sanitized chains stay as evidence but never raise a finding.
    scan = ScanResult(root=str(FIX / lang), routes=[], taint_chains=chains)
    assert not [f for f in generate_findings(scan) if "taint-chain" in f.tags]


def test_re_escape_elsewhere_does_not_sanitize_ssti() -> None:
    path = FIX / "py" / "ssti_re_escape.py"
    chain = _at_sink(_chains("py", "ssti_re_escape.py", "POST", "/preview"), "ssti", _marker(path, "sink"))
    assert chain.sanitized is False and chain.sanitizer_evidence is None
    assert chain.source_line == _marker(path, "source")


# ---------------------------------------------------------------------------
# Argument awareness and flow binding
# ---------------------------------------------------------------------------


def _flask(tmp_path: Path, body: str, route: str = "/r", method: str = "GET") -> list[TaintChain]:
    src = (
        "import ipaddress, logging, os, shlex, subprocess\n"
        "import requests\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        f'@app.route("{route}")\n'
        "def handler():\n"
        f"{body}\n"
    )
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    scan = ScanResult(root=str(tmp_path), routes=[Route(path=route, method=method, file="app.py", line=6)])
    return analyze_taint(scan, tmp_path)


def test_tainted_json_body_of_constant_url_is_not_ssrf(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    sku = request.args["sku"]\n'
        '    requests.post("https://fulfillment.example.com/dispatch", json={"sku": sku})',
    )
    assert not [c for c in chains if c.sink_kind == "ssrf"]


def test_fixed_scheme_and_host_prefix_is_not_ssrf(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    order_id = request.args["id"]\n'
        '    requests.get(f"https://shipping.example.com/orders/{order_id}")',
    )
    assert not [c for c in chains if c.sink_kind == "ssrf"]


def test_tainted_host_in_url_is_ssrf(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    host = request.args["host"]\n'
        '    requests.get(f"http://{host}/status")',
    )
    ssrf = [c for c in chains if c.sink_kind == "ssrf"]
    assert ssrf and ssrf[0].source_line == 8


def test_ip_address_used_only_for_logging_does_not_sanitize_ssrf(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    target = request.args["url"]\n'
        "    logging.info('peer %s', ipaddress.ip_address(request.remote_addr))\n"
        "    requests.get(target)",
    )
    ssrf = [c for c in chains if c.sink_kind == "ssrf"]
    assert ssrf and ssrf[0].sanitized is False


def test_sanitizer_on_a_different_variable_does_not_neutralize(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    host = request.args["host"]\n'
        '    label = shlex.quote(request.args["label"])\n'
        '    subprocess.run("dig " + host + " # " + label, shell=True)',
    )
    shell = [c for c in chains if c.sink_kind == "subprocess_shell"]
    assert shell and shell[0].sanitized is False and shell[0].source_line == 8


def test_env_only_value_is_not_a_request_source(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    cmd = os.environ["BACKUP_CMD"]\n'
        "    subprocess.run(cmd, shell=True)",
    )
    shell = [c for c in chains if c.sink_kind == "subprocess_shell"]
    assert shell and shell[0].source_kind is None and not shell[0].flow


def test_flow_is_attributed_only_to_the_enclosing_handler(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/health")\n'
        "def health():\n"
        "    return 'ok'\n\n"
        '@app.route("/fetch")\n'
        "def fetch():\n"
        '    target = request.args["url"]\n'
        "    return requests.get(target).text\n",
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[
            Route(path="/health", method="GET", file="app.py", line=5),
            Route(path="/fetch", method="GET", file="app.py", line=9),
        ],
    )
    ssrf = [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "ssrf"]
    assert [(c.route_path, c.source_line) for c in ssrf] == [("/fetch", 11)]


def test_parameter_tuple_does_not_hide_a_request_built_query(tmp_path: Path) -> None:
    chains = _flask(
        tmp_path,
        '    term = request.args["q"]\n'
        '    query = "SELECT * FROM t WHERE a = ? AND b LIKE \'" + term + "\'"\n'
        "    cursor.execute(query, (1,))",
    )
    sql = [c for c in chains if c.sink_kind == "sql_execute"]
    assert sql and sql[0].source_line == 8


def test_fastapi_handler_parameters_are_sources(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "import sqlite3\n"
        "app = FastAPI()\n\n"
        '@app.get("/items/{item_id}")\n'
        "def read_item(item_id: int, q: str):\n"
        "    db = sqlite3.connect('x.db')\n"
        "    db.execute(f'select * from items where id = {item_id}')\n"
        "    db.execute(f'select * from items where name = {q!r}')\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/items/{item_id}", method="GET", file="app.py", line=5)])
    by_line = {c.sink_line: c for c in analyze_taint(scan, tmp_path)}
    assert by_line[8].source_kind is None  # `item_id: int` is coerced — not injectable
    assert by_line[9].source_kind == "query" and by_line[9].source_line == 6


def test_js_destructuring_and_go_decode_targets_propagate(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/proxy', async (req, res) => {\n"
        "  const { url } = req.query;\n"
        "  const r = await fetch(url);\n"
        "  res.send(await r.text());\n"
        "});\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        "package main\n\n"
        'import (\n\t"encoding/json"\n\t"net/http"\n\t"os/exec"\n)\n\n'
        "type job struct{ Cmd string }\n\n"
        "func run(w http.ResponseWriter, r *http.Request) {\n"
        "\tvar j job\n"
        "\tjson.NewDecoder(r.Body).Decode(&j)\n"
        '\texec.Command("sh", "-c", j.Cmd).Run()\n'
        "}\n",
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[
            Route(path="/proxy", method="GET", file="server.js", line=3),
            Route(path="/run", method="POST", file="main.go", line=11),
        ],
    )
    chains = analyze_taint(scan, tmp_path)
    js = [c for c in chains if c.sink_kind == "ssrf" and c.sink_file == "server.js"]
    go = [c for c in chains if c.sink_kind == "subprocess_shell" and c.sink_file == "main.go"]
    assert js and js[0].source_line == 4
    assert go and go[0].source_kind == "body" and go[0].source_line == 13


# ---------------------------------------------------------------------------
# Findings, SARIF codeFlows, bench corpus
# ---------------------------------------------------------------------------


def test_orders_demo_sql_injection_finding_cites_every_traced_route() -> None:
    scan = scan_repo(REPO_ROOT / "examples" / "orders-api-demo")
    sqli = [f for f in generate_findings(scan) if f.rule_id == "sql-injection"]
    assert len(sqli) == 1
    flows = [e for e in sqli[0].evidence if e.startswith("flow: ")]
    assert any("POST /orders " in e and "app.py:16" in e and "app.py:23" in e for e in flows)
    assert any("GET /orders/search " in e and "app.py:39" in e for e in flows)
    assert any("POST /internal/reindex " in e and "app.py:50" in e for e in flows)
    # Only the handler that encloses each sink is cited for it.
    assert not any("POST /orders " in e and "app.py:39" in e for e in flows)


def test_traced_flow_is_emitted_as_a_sarif_code_flow() -> None:
    scan = scan_repo(REPO_ROOT / "examples" / "orders-api-demo")
    findings = [f for f in generate_findings(scan) if f.rule_id == "sql-injection"]
    results = build_sarif(findings)["runs"][0]["results"]
    with_flows = [r for r in results if "codeFlows" in r]
    assert with_flows
    sink_line = with_flows[0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    steps = with_flows[0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert steps[0]["kinds"] == ["source"] and steps[-1]["kinds"] == ["sink"]
    assert steps[-1]["location"]["physicalLocation"]["region"]["startLine"] == sink_line


def test_unbound_sanitizer_elsewhere_in_file_still_reports(tmp_path: Path) -> None:
    """The pre-#239 file-level rule let *any* shlex.quote in the file silence
    every shell sink; a sanitizer in another function no longer does."""
    (tmp_path / "app.py").write_text(
        "import shlex, subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "def quote_for_log(x):\n"
        "    return shlex.quote(x)\n\n"
        '@app.route("/dig")\n'
        "def dig():\n"
        '    host = request.args["host"]\n'
        '    subprocess.run("dig " + host, shell=True)\n',
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    shell = [c for c in scan.taint_chains if c.sink_kind == "subprocess_shell"]
    assert shell and shell[0].sanitized is False
    assert any("command execution" in f.title.lower() for f in generate_findings(scan))


def test_flow_pass_stays_linear_on_a_large_file(tmp_path: Path) -> None:
    funcs = "".join(
        f'@app.route("/r{i}")\n'
        f"def h{i}():\n"
        f'    a{i} = request.args["x"]\n'
        f"    b{i} = a{i} + 'x'\n"
        f"    requests.get(b{i})\n"
        f"    cursor.execute('select ' + b{i})\n\n"
        for i in range(1500)
    )
    (tmp_path / "big.py").write_text(
        "import requests\nfrom flask import Flask, request\napp = Flask(__name__)\n\n" + funcs,
        encoding="utf-8",
    )
    (tmp_path / "big.js").write_text(
        "".join(
            f"app.get('/r{i}', (req, res) => {{\n  const a = req.query.x;\n  fetch(a);\n}});\n"
            for i in range(1500)
        ),
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/r0", method="GET", file="big.py", line=5), Route(path="/r0", method="GET", file="big.js", line=1)],
    )
    start = time.perf_counter()
    chains = analyze_taint(scan, tmp_path)
    assert time.perf_counter() - start < 20
    assert any(c.source_kind for c in chains)


def test_generic_signatures_do_not_fire_on_java_method_names(tmp_path: Path) -> None:
    (tmp_path / "JobController.java").write_text(
        "@RestController\n"
        "public class JobController {\n"
        '    @PostMapping("/jobs")\n'
        "    public String run(@RequestParam String name) {\n"
        "        return exec(name);\n"
        "    }\n\n"
        "    private String exec(String name) {\n"
        '        return "queued " + name;\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/jobs", method="POST", file="JobController.java", line=3)])
    assert analyze_taint(scan, tmp_path) == []
