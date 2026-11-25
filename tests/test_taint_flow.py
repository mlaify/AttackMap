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
    # Only the fixture's own route: the other PHP fixtures in the directory are
    # script entry points of their own (#453).
    return [c for c in analyze_taint(scan, root) if c.route_file == name]


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


# Redirect targets (#327): a literal that pins scheme + host and closes the
# authority leaves request data only in the path/query/fragment, which can't
# send the user to another site.

_REDIRECT_ROUTES_JS = [
    # (route, redirect argument, expected open redirect)
    ("/sso/start", "`https://sso.example.com/authorize?${new URLSearchParams({ login_hint: req.query.email })}`", False),
    ("/sso/query", "'https://sso.example.com?next=' + req.query.next", False),
    ("/sso/fragment", "`https://app.example.com#${req.query.tab}`", False),
    ("/sso/path", "'https://docs.example.com/' + req.query.page", False),
    ("/local", "`/orders/${req.query.id}`", False),
    ("/bad/host", "`https://${req.query.host}/welcome`", True),
    ("/bad/suffix", "`https://sso.example.com${req.query.p}`", True),
    ("/bad/userinfo", "'https://sso.example.com' + req.query.p", True),
    ("/bad/scheme", "`${req.query.scheme}://sso.example.com/`", True),
    ("/bad/start", "req.query.next", True),
    ("/bad/protocol-relative", "'//' + req.query.host", True),
    ("/bad/script", "'javascript://example.com/' + req.query.code", True),
]


def _tainted_redirects(chains: list[TaintChain]) -> set[tuple[str, int]]:
    return {
        (c.route_path, c.sink_line)
        for c in chains
        if c.sink_kind == "open_redirect" and c.source_kind and not c.sanitized
    }


def test_redirect_to_a_fixed_host_is_not_an_open_redirect_js(tmp_path: Path) -> None:
    lines = ["const express = require('express');", "const app = express();"]
    routes: list[Route] = []
    sinks: dict[str, int] = {}
    for path, target, _ in _REDIRECT_ROUTES_JS:
        lines.append(f"app.get('{path}', (req, res) => {{")
        routes.append(Route(path=path, method="GET", file="server.js", line=len(lines)))
        lines.append(f"  res.redirect({target});")
        sinks[path] = len(lines)
        lines.append("});")
    (tmp_path / "server.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
    scan = ScanResult(root=str(tmp_path), routes=routes)
    found = _tainted_redirects(analyze_taint(scan, tmp_path))
    expected = {(path, sinks[path]) for path, _, vuln in _REDIRECT_ROUTES_JS if vuln}
    assert found == expected


@pytest.mark.parametrize(
    "target, vulnerable",
    [
        ('f"https://sso.example.com/authorize?{urlencode(dict(hint=q))}"', False),
        ('f"https://sso.example.com/?next={q}"', False),
        ('"https://sso.example.com?next=%s" % q', False),
        ('"https://sso.example.com/{}".format(q)', False),
        ('f"https://{q}/welcome"', True),
        ('f"https://sso.example.com{q}"', True),
        ('f"//{q}"', True),
        ("q", True),
    ],
)
def test_redirect_to_a_fixed_host_is_not_an_open_redirect_py(tmp_path: Path, target: str, vulnerable: bool) -> None:
    chains = _flask(tmp_path, f'    q = request.args["next"]\n    return redirect({target})')
    assert bool(_tainted_redirects(chains)) is vulnerable


def test_fixed_host_redirect_raises_no_finding_but_a_tainted_host_does(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/sso/start', (req, res) => {\n"
        "  const params = new URLSearchParams({ client_id: 'web', login_hint: req.query.email });\n"
        "  res.redirect(`https://sso.example.com/authorize?${params}`);\n"
        "});\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert not [f for f in generate_findings(scan) if f.rule_id == "open-redirect"]
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/sso/start', (req, res) => {\n"
        "  res.redirect(`https://${req.query.idp}/authorize`);\n"
        "});\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert [f for f in generate_findings(scan) if f.rule_id == "open-redirect"]


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


# ---------- Concise arrow handlers (#398) ----------

_CONCISE_APP = (
    "const express = require('express');\n"
    "const mysql = require('mysql');\n"
    "const conn = mysql.createConnection({});\n"
    "const app = express();\n"
    "app.get('/a', (req, res) => conn.query('SELECT * FROM t WHERE id = ' + req.query.id));\n"
    "app.get('/safe', (req, res) => conn.query('SELECT * FROM t WHERE id = ?', [req.query.id]));\n"
    "app.get('/multi', async (req, res) =>\n"
    "  conn.query('SELECT * FROM t WHERE name = ' + req.query.name));\n"
    "app.get('/b', (req, res) => { conn.query('SELECT * FROM t WHERE id = ' + req.query.id); });\n"
)


def _sqli_lines(scan: ScanResult) -> set[int]:
    return {
        loc.line
        for f in generate_findings(scan)
        if f.rule_id == "sql-injection"
        for loc in f.locations
        if loc.line is not None
    }


def test_concise_arrow_handler_is_taint_walked(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(_CONCISE_APP, encoding="utf-8")
    scan = scan_repo(tmp_path)
    # /a (one line), /multi (body on the next line) and the braced /b; not the
    # parameterized /safe.
    assert _sqli_lines(scan) == {5, 8, 9}
    traced = {(c.route_path, c.sink_line) for c in scan.taint_chains if c.source_kind is not None}
    assert {("/a", 5), ("/multi", 8), ("/b", 9)} <= traced
    # Each concise handler is its own function: /a's input isn't traced into
    # /b's sink (it may still list it as an untraced same-file reach).
    assert not [c for c in scan.taint_chains if c.route_path == "/a" and c.sink_line == 9 and c.source_kind]


def test_concise_arrow_handler_in_a_router_module(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const users = require('./users');\n"
        "const app = express();\n"
        "app.use('/api/users', users);\n",
        encoding="utf-8",
    )
    (tmp_path / "users.js").write_text(
        "const router = require('express').Router();\n"
        "const db = require('./db');\n"
        "router.get('/:id', (req, res) => db.query('SELECT * FROM users WHERE id = ' + req.params.id));\n"
        "module.exports = router;\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert [f for f in generate_findings(scan) if f.rule_id == "sql-injection"]


def test_concise_bodies_do_not_swallow_their_neighbours(tmp_path: Path) -> None:
    from attackmap.taint_flow import _TextFlow

    src = (
        "const f = (a, b) => a + b, g = x => ({ y: x });\n"
        "items.map(i => i.id).filter(Boolean);\n"
        "function h(req) { return run(() => req.query.x); }\n"
    )
    flow = _TextFlow(src, "js")
    bodies = [src[o + 1 : c].strip() for o, c in flow._concise_bodies()]
    assert bodies == ["a + b", "({ y: x })", "i.id", "req.query.x"]


def test_typescript_annotated_declarations_carry_taint(tmp_path: Path) -> None:
    # #442: `let x: T = req…` binds x, not the type name.
    (tmp_path / "s.ts").write_text(
        "export function s () {\n  return (req, res) => {\n"
        "    const criteria: string | undefined = req.query.q as string\n"
        "    models.sequelize.query(`SELECT * FROM P WHERE name LIKE '%${criteria}%'`, { model: P })\n  }\n}\n"
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/s", method="GET", file="s.ts", line=2)])
    assert [(c.sink_kind, c.source_kind) for c in analyze_taint(scan, tmp_path)] == [("sql_execute", "query")]


@pytest.mark.parametrize(
    ("guard", "sanitized"),
    [
        # #455: DVWA exec/impossible.php — each octet checked numeric in an enclosing if.
        ("if (is_numeric($octet[0]) && is_numeric($octet[1]) && sizeof($octet) == 2) {", True),
        ("if (filter_var($target, FILTER_VALIDATE_IP)) {", True),
        ("if (strlen($target) < 64) {", False),
    ],
)
def test_numeric_validation_guards_command_injection(tmp_path: Path, guard: str, sanitized: bool) -> None:
    (tmp_path / "ping.php").write_text(
        "<?php\n$target = $_REQUEST['ip'];\n$octet = explode('.', $target);\n"
        f"{guard}\n    $target = $octet[0] . '.' . $octet[1];\n    $cmd = shell_exec('ping ' . $target);\n}}\n"
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/ping.php", method="POST", file="ping.php")])
    [chain] = [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "subprocess_shell"]
    assert chain.sanitized is sanitized and chain.source_kind == "body"


_HELPER_CONTROLLER = (
    "@RestController\n"
    "public class Lesson {\n"
    '    @PostMapping("/a")\n'
    "    public String a(@RequestParam String name) {\n"
    "        return injectable(name);\n"
    "    }\n\n"
    '    @PostMapping("/b")\n'
    "    public String b(@RequestParam String name) {\n"
    "        String safe = String.valueOf(name.length());\n"
    "        return run(safe);\n"
    "    }\n\n"
    "    protected String injectable(String accountName) {\n"
    "        String query = \"SELECT * FROM t WHERE n = '\" + accountName + \"'\";\n"
    "        return run(query);\n"
    "    }\n\n"
    "    private String run(String query) {\n"
    "        Statement statement = connection.createStatement();\n"
    "        statement.executeQuery(query);\n"  # line 21
    '        return "ok";\n'
    "    }\n"
    "}\n"
)


def test_request_input_is_followed_into_same_file_helpers(tmp_path: Path) -> None:
    # WebGoat: completed(@RequestParam q) -> injectableQuery(q) -> helper -> executeQuery.
    (tmp_path / "Lesson.java").write_text(_HELPER_CONTROLLER, encoding="utf-8")
    routes = [Route(path=p, method="POST", file="Lesson.java", line=ln) for p, ln in (("/a", 3), ("/b", 8))]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    traced = [c for c in chains if c.sink_kind == "sql_execute" and c.source_kind]
    # Two calls up from the sink to /a's handler parameter; /b passes a length,
    # and /a's input is not credited to /b.
    assert [(c.route_path, c.sink_line, c.source_line) for c in traced] == [("/a", 21, 4)]


@pytest.mark.parametrize(
    ("ret", "fires"),
    [
        ('return new ModelAndView("redirect:" + url);', True),
        ('return "redirect:" + url;', True),
        ('response.sendRedirect(url); return null;', True),
        ('return new ModelAndView("redirect:/home?u=" + url);', False),  # same-site path pinned
        ('return new ModelAndView("lessons/" + url);', False),  # a view name, not a redirect
    ],
)
def test_spring_redirect_sinks(tmp_path: Path, ret: str, fires: bool) -> None:
    (tmp_path / "R.java").write_text(
        '@Controller\npublic class R {\n  @GetMapping("/r")\n'
        f"  public ModelAndView r(@RequestParam String url, HttpServletResponse response) {{\n    {ret}\n  }}\n}}\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/r", method="GET", file="R.java", line=3)])
    hits = [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "open_redirect" and c.source_kind and not c.sanitized]
    assert bool(hits) is fires


def test_java_string_matches_is_a_full_match_guard(tmp_path: Path) -> None:
    # WebGoat SSRFTask2: only the exact allowed URL is ever fetched.
    (tmp_path / "S.java").write_text(
        '@RestController\npublic class S {\n  @PostMapping("/s")\n  public String s(@RequestParam String url) {\n'
        '    if (url.matches("http://ifconfig\\\\.pro")) {\n'
        "      try (InputStream in = new URL(url).openStream()) { return \"x\"; }\n"
        '    }\n    return "no";\n  }\n}\n',
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/s", method="POST", file="S.java", line=3)])
    [chain] = [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "ssrf"]
    assert chain.sanitized


def test_a_not_found_exit_after_a_lookup_validates_the_key(tmp_path: Path) -> None:
    # Juice Shop vulnCodeSnippet (#444): the key named a stored record, or the handler returned. The record
    # itself may hold attacker-written data (Juice Shop's stored username SSTI), except its id, which the
    # server assigned (profileImageFileUpload). A bare presence check of the raw input proves nothing.
    (tmp_path / "app.js").write_text(
        "app.post('/a', async (req, res) => {\n"
        "  const key = req.body.key\n"
        "  const snippet = await retrieveSnippet(key)\n"
        "  if (snippet == null) { return res.status(404).end() }\n"
        "  fs.readFileSync('./data/' + key + '.yml')\n"
        "})\n"
        "app.post('/b', (req, res) => {\n"
        "  const user = sessions.get(req.cookies.token)\n"
        "  if (!user) { return next(new Error('blocked')) }\n"
        "  fs.writeFileSync(`uploads/${user.data.id}.png`, buf)\n"
        "})\n"
        "app.post('/c', (req, res) => {\n"
        "  const key = req.body.key\n"
        "  if (!key) { return res.status(400).end() }\n"
        "  fs.readFileSync('./data/' + key)\n"
        "})\n"
        "app.post('/d', async (req, res) => {\n"
        "  const key = req.body.key\n"
        "  let rec\n"
        "  try {\n"
        "    rec = await retrieveSnippet(key)\n"
        "    if (rec == null) { return res.status(404).end() }\n"
        "  } catch (e) { return next(e) }\n"
        "  fs.readFileSync('./data/' + key)\n"
        "})\n"
        "app.post('/e', (req, res) => {\n"
        "  const key = req.body.key\n"
        "  const fixes = readFixes(key)\n"
        "  if (fixes.items.length === 0) { res.status(404).end() } else { fs.readFileSync('./f/' + key) }\n"
        "  if (fixes) { res.end() } else { fs.readFileSync('./g/' + key) }\n"
        "})\n"
        "app.post('/f', (req, res) => {\n"
        "  const user = sessions.get(req.cookies.token)\n"
        "  fs.writeFileSync(`t/${user.name}`, buf)\n"
        "})\n",
        encoding="utf-8",
    )
    spec = (("/a", 1), ("/b", 7), ("/c", 12), ("/d", 17), ("/e", 26), ("/f", 32))
    routes = [Route(path=p, method="POST", file="app.js", line=n) for p, n in spec]
    chains = [c for c in analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path) if c.sink_kind == "dynamic_open"]
    assert sorted((c.sink_line, c.sanitized) for c in chains) == [
        (5, True), (15, False), (24, True), (29, True), (30, False), (34, False)
    ]  # /b: the record's server-assigned id carries no taint; /f: its other fields do


def test_destructured_express_request_and_vm_context_eval(tmp_path: Path) -> None:
    # Juice Shop b2bOrder / redirect (#445): `({ body }: Request, res)` destructures the request; the fixed
    # vm code `safeEval(x)` evaluates a context variable. Destructured props of a non-handler stay untainted.
    (tmp_path / "a.ts").write_text(
        "app.post('/b', ({ body }: Request, res: Response) => {\n"
        "  const lines = body.orderLinesData || ''\n"
        "  vm.runInContext('safeEval(lines)', { safeEval, lines }, { timeout: 2000 })\n"
        "  vm.runInContext('render(lines)', { lines })\n"
        "})\n"
        "app.get('/r', ({ query: q }, res) => {\n"
        "  res.redirect(q.to)\n"
        "})\n"
        "function Search({ query }) { return eval(query) }\n",
        encoding="utf-8",
    )
    routes = [Route(path="/b", method="POST", file="a.ts", line=1), Route(path="/r", method="GET", file="a.ts", line=6)]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    assert {(c.sink_kind, c.sink_line, c.source_kind) for c in chains if c.source_kind} == {
        ("code_injection", 3, "body"),
        ("open_redirect", 7, "query"),
    }


def test_the_whole_request_as_render_locals_is_template_injection(tmp_path: Path) -> None:
    # Juice Shop dataErasure (#445): `layout` and engine options come from the request. Picking fields is fine.
    (tmp_path / "a.js").write_text(
        "app.post('/a', (req, res) => {\n"
        "  res.render('result', { ...req.body, ...themeVars }, (e, html) => res.send(html))\n"
        "})\n"
        "app.post('/b', (req, res) => {\n"
        "  res.render('result', req.query)\n"
        "})\n"
        "app.post('/c', (req, res) => {\n"
        "  res.render('profile', { username: req.body.name, title: 'x' })\n"
        "})\n",
        encoding="utf-8",
    )
    routes = [Route(path=p, method="POST", file="a.js", line=n) for p, n in (("/a", 1), ("/b", 4), ("/c", 7))]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    assert {(c.route_path, c.sink_line, c.source_kind) for c in chains if c.source_kind} == {("/a", 2, "body"), ("/b", 5, "query")}
    assert not [c for c in chains if c.sink_line == 8]


def test_request_input_is_followed_into_a_helper_in_another_file(tmp_path: Path) -> None:
    # WebGoat CommandInjectionTask2 → CommandExecutionService (same package, no import): one hop across
    # files, only when the call passes request input. A Java helper with no traced caller adds nothing.
    pkg = tmp_path / "src/main/java/org/x"
    pkg.mkdir(parents=True)
    (pkg / "Task.java").write_text(
        "@RestController\npublic class Task {\n  private final ExecService svc;\n"
        '  @PostMapping("/run")\n  public String run(@RequestParam String command) {\n'
        "    return svc.execute(null, command).out();\n  }\n"
        '  @PostMapping("/fixed")\n  public String fixed(@RequestParam String q) {\n'
        '    return svc.execute(null, "uname -a").out() + svc.render(q);\n  }\n}\n',
        encoding="utf-8",
    )
    (pkg / "ExecService.java").write_text(
        "public class ExecService {\n"
        "  public Result execute(File dir, String command) {\n"
        '    return run(dir, new ProcessBuilder("/bin/sh", "-c", command));\n  }\n'
        "  public String render(String name) { return name; }\n"
        "  public Result other(String c) {\n    return run(null, new ProcessBuilder(c));\n  }\n}\n",
        encoding="utf-8",
    )
    task = "src/main/java/org/x/Task.java"
    routes = [Route(path="/run", method="POST", file=task, line=4), Route(path="/fixed", method="POST", file=task, line=8)]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    assert [(c.route_path, c.sink_file.rsplit("/", 1)[1], c.sink_line, c.source_kind) for c in chains] == [
        ("/run", "ExecService.java", 3, "query")
    ]
    assert [(s.file.rsplit("/", 1)[1], s.line, s.kind) for s in chains[0].flow][-1] == ("ExecService.java", 3, "sink")


def test_js_request_input_into_an_imported_helper_is_traced(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const { runQuery } = require('./db');\n"
        "app.get('/a', (req, res) => { res.json(runQuery(req.query.id)); });\n"
        "app.get('/b', (req, res) => { res.json(runQuery(42)); });\n",
        encoding="utf-8",
    )
    (tmp_path / "db.js").write_text(
        "function runQuery(id) {\n  return conn.query('SELECT * FROM t WHERE id = ' + id);\n}\nmodule.exports = { runQuery };\n",
        encoding="utf-8",
    )
    routes = [Route(path="/a", method="GET", file="app.js", line=2), Route(path="/b", method="GET", file="app.js", line=3)]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    traced = [(c.route_path, c.sink_file, c.sink_line, c.source_kind) for c in chains if c.source_kind]
    assert traced == [("/a", "db.js", 2, "query")]  # /b keeps an untraced reach chain


def test_xxe_needs_unconditional_parser_hardening(tmp_path: Path) -> None:
    # WebGoat CommentsCache: hardening behind `if (securityEnabled)` doesn't hold for callers passing false.
    pkg = tmp_path / "src/main/java/org/x"
    pkg.mkdir(parents=True)
    (pkg / "Xxe.java").write_text(
        "@RestController\npublic class Xxe {\n  private Comments comments;\n  private Safe safe;\n"
        '  @PostMapping("/xxe")\n  public Object post(@RequestBody String body) {\n'
        "    return comments.parseXml(body, false) + safe.parse(body);\n  }\n}\n",
        encoding="utf-8",
    )
    reader = "    var xsr = xif.createXMLStreamReader(new StringReader(xml));\n    return xsr;\n  }\n}\n"
    (pkg / "Comments.java").write_text(
        "public class Comments {\n  public Object parseXml(String xml, boolean securityEnabled) {\n"
        "    var xif = XMLInputFactory.newInstance();\n    if (securityEnabled) {\n"
        '      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n    }\n' + reader,
        encoding="utf-8",
    )
    (pkg / "Safe.java").write_text(
        "public class Safe {\n  public Object parse(String xml) {\n    var xif = XMLInputFactory.newInstance();\n"
        "    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n" + reader,
        encoding="utf-8",
    )
    routes = [Route(path="/xxe", method="POST", file="src/main/java/org/x/Xxe.java", line=5)]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    assert [(c.sink_file.rsplit("/", 1)[1], c.sink_line, c.sink_kind) for c in chains] == [("Comments.java", 7, "xml_external_entity")]


def test_libxml_entity_parse_in_a_vm_context_is_xxe(tmp_path: Path) -> None:
    # Juice Shop lib/xml.ts: XML_PARSE_NOENT parse run as fixed vm code over the uploaded data.
    (tmp_path / "upload.js").write_text(
        "const { parseXmlString } = require('./xml');\n"
        "app.post('/upload', (req, res) => { res.send(parseXmlString(req.body.xml)); });\n",
        encoding="utf-8",
    )
    (tmp_path / "xml.js").write_text(
        "function parseXmlString(data) {\n  const option = libxml2.ParseOption.XML_PARSE_NOENT;\n"
        "  const sandbox = { libxml2, data, option };\n"
        "  return vm.runInContext('libxml2.XmlDocument.fromString(data, { option })', sandbox);\n}\n"
        "module.exports = { parseXmlString };\n",
        encoding="utf-8",
    )
    routes = [Route(path="/upload", method="POST", file="upload.js", line=2)]
    chains = analyze_taint(ScanResult(root=str(tmp_path), routes=routes), tmp_path)
    assert [(c.sink_file, c.sink_line, c.sink_kind, c.source_kind) for c in chains] == [("xml.js", 4, "xml_external_entity", "body")]
