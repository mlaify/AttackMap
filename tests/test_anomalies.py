"""Tests for the anomaly / outlier detector (#78)."""

from __future__ import annotations

from pathlib import Path

from attackmap.anomalies import _peer_key, find_anomalies
from attackmap.models import Route, ScanResult, TaintChain
from attackmap.threat_model import generate_findings


def _line_of(content: str, needle: str) -> int:
    for i, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"needle not found: {needle!r}")


def _scan_with_routes(tmp_path: Path, filename: str, content: str, specs) -> ScanResult:
    """Write ``content`` to ``filename`` and build a ScanResult whose routes
    point at the given (path, method, needle) specs."""
    (tmp_path / filename).write_text(content, encoding="utf-8")
    routes = [
        Route(path=p, method=m, file=filename, line=_line_of(content, needle))
        for (p, m, needle) in specs
    ]
    return ScanResult(root=str(tmp_path), routes=routes)


# ---------------------------------------------------------------------------
# peer key
# ---------------------------------------------------------------------------


def test_peer_key_prefix_before_param() -> None:
    assert _peer_key("/api/users/{id}") == "api/users"
    assert _peer_key("/api/users") == "api/users"
    assert _peer_key("/api/v1/users/{id}/settings") == "api/v1/users"
    assert _peer_key("/users/:id/posts") == "users"


def test_peer_key_no_static_prefix() -> None:
    assert _peer_key("/{id}") is None
    assert _peer_key("/") is None


# ---------------------------------------------------------------------------
# auth outlier
# ---------------------------------------------------------------------------

_AUTH_COHORT = """\
from flask import Blueprint
bp = Blueprint("users", __name__)


@bp.route("/api/users")
@login_required
def list_users():
    return db.all()


@bp.route("/api/users/<id>")
@login_required
def get_user(id):
    return db.get(id)


@bp.route("/api/users/<id>/settings")
@login_required
def settings(id):
    return db.settings(id)


@bp.route("/api/users/export")
def export_users():
    return db.dump()
"""


def test_auth_outlier_detected(tmp_path: Path) -> None:
    scan = _scan_with_routes(
        tmp_path,
        "views.py",
        _AUTH_COHORT,
        [
            ("/api/users", "GET", '"/api/users")'),
            ("/api/users/<id>", "GET", '"/api/users/<id>")'),
            ("/api/users/<id>/settings", "GET", '"/api/users/<id>/settings")'),
            ("/api/users/export", "GET", '"/api/users/export")'),
        ],
    )
    anomalies = find_anomalies(scan)
    auth = [a for a in anomalies if a.kind == "auth_outlier"]
    assert len(auth) == 1
    assert auth[0].route_path == "/api/users/export"
    assert auth[0].peer_group == "api/users"
    assert auth[0].consistent_peers == 3
    assert auth[0].peer_group_size == 4
    assert auth[0].confidence > 0.5


def test_all_authed_cohort_no_outlier(tmp_path: Path) -> None:
    content = _AUTH_COHORT.replace(
        '@bp.route("/api/users/export")\ndef export_users():',
        '@bp.route("/api/users/export")\n@login_required\ndef export_users():',
    )
    scan = _scan_with_routes(
        tmp_path,
        "views.py",
        content,
        [
            ("/api/users", "GET", '"/api/users")'),
            ("/api/users/<id>", "GET", '"/api/users/<id>")'),
            ("/api/users/<id>/settings", "GET", '"/api/users/<id>/settings")'),
            ("/api/users/export", "GET", '"/api/users/export")'),
        ],
    )
    assert not [a for a in find_anomalies(scan) if a.kind == "auth_outlier"]


def test_split_cohort_not_flagged(tmp_path: Path) -> None:
    # 2 authed, 2 unauthed = 50/50 → not an outlier, no nagging.
    content = """\
@bp.route("/api/items")
@login_required
def a():
    pass


@bp.route("/api/items/<id>")
@login_required
def b(id):
    pass


@bp.route("/api/items/search")
def c():
    pass


@bp.route("/api/items/recent")
def d():
    pass
"""
    scan = _scan_with_routes(
        tmp_path,
        "items.py",
        content,
        [
            ("/api/items", "GET", '"/api/items")'),
            ("/api/items/<id>", "GET", '"/api/items/<id>")'),
            ("/api/items/search", "GET", '"/api/items/search")'),
            ("/api/items/recent", "GET", '"/api/items/recent")'),
        ],
    )
    assert not [a for a in find_anomalies(scan) if a.kind == "auth_outlier"]


def test_small_group_below_threshold(tmp_path: Path) -> None:
    # Only 2 routes in the cohort — too small to establish a norm.
    content = """\
@bp.route("/api/x")
@login_required
def a():
    pass


@bp.route("/api/x/go")
def b():
    pass
"""
    scan = _scan_with_routes(
        tmp_path,
        "x.py",
        content,
        [
            ("/api/x", "GET", '"/api/x")'),
            ("/api/x/go", "GET", '"/api/x/go")'),
        ],
    )
    assert find_anomalies(scan) == []


def test_confidence_scales_with_group(tmp_path: Path) -> None:
    # A big consistent cohort should yield higher confidence than a small one.
    lines = ["from flask import Blueprint", "bp = Blueprint('m', __name__)", ""]
    specs = []
    for i in range(6):
        lines += [f'@bp.route("/api/big/r{i}")', "@login_required", f"def r{i}():", "    pass", ""]
        specs.append((f"/api/big/r{i}", "GET", f'"/api/big/r{i}")'))
    # one outlier without auth
    lines += ['@bp.route("/api/big/odd")', "def odd():", "    pass", ""]
    specs.append(("/api/big/odd", "GET", '"/api/big/odd")'))
    scan = _scan_with_routes(tmp_path, "big.py", "\n".join(lines), specs)
    auth = [a for a in find_anomalies(scan) if a.kind == "auth_outlier"]
    assert len(auth) == 1
    assert auth[0].consistent_peers == 6
    assert auth[0].confidence >= 0.85


# ---------------------------------------------------------------------------
# method outlier
# ---------------------------------------------------------------------------


def test_method_outlier_lone_writer(tmp_path: Path) -> None:
    content = """\
@bp.route("/api/report")
def a():
    pass


@bp.route("/api/report/<id>")
def b(id):
    pass


@bp.route("/api/report/summary")
def c():
    pass


@bp.route("/api/report/latest")
def d():
    pass


@bp.route("/api/report/purge")
def e():
    pass
"""
    scan = _scan_with_routes(
        tmp_path,
        "report.py",
        content,
        [
            ("/api/report", "GET", '"/api/report")'),
            ("/api/report/<id>", "GET", '"/api/report/<id>")'),
            ("/api/report/summary", "GET", '"/api/report/summary")'),
            ("/api/report/latest", "GET", '"/api/report/latest")'),
            ("/api/report/purge", "DELETE", '"/api/report/purge")'),
        ],
    )
    method = [a for a in find_anomalies(scan) if a.kind == "method_outlier"]
    assert len(method) == 1
    assert method[0].route_method == "DELETE"
    assert method[0].route_path == "/api/report/purge"


def test_normal_crud_not_method_outlier(tmp_path: Path) -> None:
    # GET list, GET detail, POST create — ordinary CRUD, only 2 readers so
    # the read cluster isn't dominant. No method outlier.
    content = """\
@bp.route("/api/todos")
def a():
    pass


@bp.route("/api/todos/<id>")
def b(id):
    pass


@bp.route("/api/todos")
def create():
    pass
"""
    scan = _scan_with_routes(
        tmp_path,
        "todos.py",
        content,
        [
            ("/api/todos", "GET", '"/api/todos")'),
            ("/api/todos/<id>", "GET", '"/api/todos/<id>")'),
            ("/api/todos", "POST", "def create"),
        ],
    )
    assert not [a for a in find_anomalies(scan) if a.kind == "method_outlier"]


# ---------------------------------------------------------------------------
# validation outlier
# ---------------------------------------------------------------------------


def test_validation_outlier_detected(tmp_path: Path) -> None:
    content = """\
@bp.route("/api/forms/a", methods=["POST"])
def a():
    schema.validate(request.json)
    return save()


@bp.route("/api/forms/b", methods=["POST"])
def b():
    schema.validate(request.json)
    return save()


@bp.route("/api/forms/c", methods=["POST"])
def c():
    data = UserSchema().parse(request.json)
    return save()


@bp.route("/api/forms/raw", methods=["POST"])
def raw():
    return save(request.json)
"""
    scan = _scan_with_routes(
        tmp_path,
        "forms.py",
        content,
        [
            ("/api/forms/a", "POST", '"/api/forms/a"'),
            ("/api/forms/b", "POST", '"/api/forms/b"'),
            ("/api/forms/c", "POST", '"/api/forms/c"'),
            ("/api/forms/raw", "POST", '"/api/forms/raw"'),
        ],
    )
    val = [a for a in find_anomalies(scan) if a.kind == "validation_outlier"]
    assert len(val) == 1
    assert val[0].route_path == "/api/forms/raw"
    assert val[0].severity == "low"


# ---------------------------------------------------------------------------
# test-file routes excluded (#67)
# ---------------------------------------------------------------------------


def test_routes_in_test_files_ignored(tmp_path: Path) -> None:
    content = _AUTH_COHORT
    (tmp_path / "test_views.py").write_text(content, encoding="utf-8")
    routes = [
        Route(path=p, method="GET", file="test_views.py", line=_line_of(content, needle))
        for (p, needle) in [
            ("/api/users", '"/api/users")'),
            ("/api/users/<id>", '"/api/users/<id>")'),
            ("/api/users/<id>/settings", '"/api/users/<id>/settings")'),
            ("/api/users/export", '"/api/users/export")'),
        ]
    ]
    scan = ScanResult(root=str(tmp_path), routes=routes)
    assert find_anomalies(scan) == []


# ---------------------------------------------------------------------------
# findings via threat_model
# ---------------------------------------------------------------------------


def test_auth_outlier_becomes_tagged_finding(tmp_path: Path) -> None:
    scan = _scan_with_routes(
        tmp_path,
        "views.py",
        _AUTH_COHORT,
        [
            ("/api/users", "GET", '"/api/users")'),
            ("/api/users/<id>", "GET", '"/api/users/<id>")'),
            ("/api/users/<id>/settings", "GET", '"/api/users/<id>/settings")'),
            ("/api/users/export", "GET", '"/api/users/export")'),
        ],
    )
    scan.anomalies = find_anomalies(scan)
    findings = [f for f in generate_findings(scan) if "anomaly" in f.tags]
    assert findings
    auth = next(f for f in findings if "Authorization outlier" in f.title)
    assert auth.severity == "high"
    assert auth.attack_techniques
    assert any("/api/users/export" in e for e in auth.evidence)


def test_progress_reported_per_cohort(tmp_path: Path) -> None:
    """find_anomalies drives a determinate begin/advance over cohorts (#status)."""
    import io
    import json

    from attackmap.progress import JsonScanProgress

    scan = _scan_with_routes(
        tmp_path,
        "views.py",
        _AUTH_COHORT,
        [
            ("/api/users", "GET", '"/api/users")'),
            ("/api/users/<id>", "GET", '"/api/users/<id>")'),
            ("/api/users/export", "GET", '"/api/users/export")'),
        ],
    )
    stream = io.StringIO()
    find_anomalies(scan, progress=JsonScanProgress(stream=stream, min_interval=0.0))
    events = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    begin = next(e for e in events if e["event"] == "begin")
    assert begin["label"] == "Anomaly / outlier detection"
    assert begin["total"] >= 1
    assert any(e["event"] == "advance" for e in events)


# ---------------------------------------------------------------------------
# invariant mining (#149a)
# ---------------------------------------------------------------------------


def _sink_cohort(
    tmp_path: Path,
    n_guarded: int,
    n_unguarded: int,
    *,
    guard: str = "    current_user.assert_can_read(id)",
    filename: str = "handlers.py",
) -> ScanResult:
    """Build a file of handlers that all reach a same-file ``db.execute`` sink,
    ``n_guarded`` of which place an auth guard before the sink line. Returns a
    ScanResult wired with the matching routes and taint chains."""
    lines: list[str] = ["from flask import Flask", "app = Flask(__name__)", ""]
    routes: list[Route] = []
    chains: list[TaintChain] = []
    total = n_guarded + n_unguarded
    for i in range(total):
        guarded = i < n_guarded
        path = f"/api/res{i}/<id>"
        route_line = len(lines) + 1  # the @app.route decorator line (1-based)
        lines.append(f'@app.route("{path}")')
        lines.append(f"def handler{i}(id):")
        if guarded:
            lines.append(guard)
        sink_line = len(lines) + 1
        lines.append('    return db.execute("SELECT * FROM t WHERE id=" + id)')
        lines.append("")
        routes.append(Route(path=path, method="GET", file=filename, line=route_line))
        chains.append(
            TaintChain(
                route_path=path,
                route_method="GET",
                route_file=filename,
                sink_kind="sql_execute",
                sink_file=filename,
                sink_line=sink_line,
                hops=0,
                files=[filename],
            )
        )
    (tmp_path / filename).write_text("\n".join(lines), encoding="utf-8")
    return ScanResult(root=str(tmp_path), routes=routes, taint_chains=chains)


def test_invariant_violation_flags_the_unguarded_handler(tmp_path: Path) -> None:
    """9 of 10 handlers guard `id` before a SQL sink; the 10th is flagged with
    the mined invariant as evidence (the #149a acceptance criterion)."""
    scan = _sink_cohort(tmp_path, n_guarded=9, n_unguarded=1)
    anomalies = find_anomalies(scan, tmp_path)

    violations = [a for a in anomalies if a.kind == "invariant_violation"]
    assert len(violations) == 1
    v = violations[0]
    assert v.route_path == "/api/res9/<id>"  # the lone unguarded handler
    assert v.peer_group == "sink:sql_execute"
    assert v.peer_group_size == 10
    assert v.consistent_peers == 9
    assert v.severity == "high"
    assert v.invariant is not None
    assert "9 of 10" in v.invariant
    assert "database (SQL execute)" in v.invariant


def test_invariant_surfaced_as_finding_evidence(tmp_path: Path) -> None:
    scan = _sink_cohort(tmp_path, n_guarded=9, n_unguarded=1)
    scan.anomalies = find_anomalies(scan, tmp_path)
    findings = generate_findings(scan, [])
    inv = next(f for f in findings if "Invariant violation" in f.title)
    assert inv.severity == "high"
    assert inv.attack_techniques
    assert any("invariant:" in e and "9 of 10" in e for e in inv.evidence)
    assert any("/api/res9/<id>" in e for e in inv.evidence)


def test_invariant_needs_strong_majority(tmp_path: Path) -> None:
    """A split cohort (5 guarded / 5 not) is not a strong-enough pattern."""
    scan = _sink_cohort(tmp_path, n_guarded=5, n_unguarded=5)
    anomalies = find_anomalies(scan, tmp_path)
    assert not [a for a in anomalies if a.kind == "invariant_violation"]


def test_invariant_needs_min_cohort(tmp_path: Path) -> None:
    """Below the cohort floor (2 guarded / 1 not = 3 < 4) nothing fires."""
    scan = _sink_cohort(tmp_path, n_guarded=2, n_unguarded=1)
    anomalies = find_anomalies(scan, tmp_path)
    assert not [a for a in anomalies if a.kind == "invariant_violation"]


def test_invariant_ignores_sanitized_chains(tmp_path: Path) -> None:
    """A sink neutralized at the sink (#137) leaves the flow out of the cohort,
    so a would-be violator whose chain is sanitized is not flagged."""
    scan = _sink_cohort(tmp_path, n_guarded=9, n_unguarded=1)
    for chain in scan.taint_chains:
        if chain.route_path == "/api/res9/<id>":
            chain.sanitized = True
            chain.sanitizer_evidence = "parameterized query"
    anomalies = find_anomalies(scan, tmp_path)
    assert not [a for a in anomalies if a.kind == "invariant_violation"]


def test_invariant_guard_must_precede_sink(tmp_path: Path) -> None:
    """A guard placed *after* the sink line does not satisfy the invariant."""
    filename = "late.py"
    lines: list[str] = ["from flask import Flask", "app = Flask(__name__)", ""]
    routes: list[Route] = []
    chains: list[TaintChain] = []
    for i in range(10):
        path = f"/api/res{i}/<id>"
        route_line = len(lines) + 1
        lines.append(f'@app.route("{path}")')
        lines.append(f"def handler{i}(id):")
        if i < 9:
            lines.append("    current_user.assert_can_read(id)")
            sink_line = len(lines) + 1
            lines.append('    return db.execute("SELECT * FROM t WHERE id=" + id)')
        else:
            # sink first, guard afterwards — ordering means this is unguarded.
            sink_line = len(lines) + 1
            lines.append('    row = db.execute("SELECT * FROM t WHERE id=" + id)')
            lines.append("    current_user.assert_can_read(id)")
            lines.append("    return row")
        lines.append("")
        routes.append(Route(path=path, method="GET", file=filename, line=route_line))
        chains.append(
            TaintChain(
                route_path=path, route_method="GET", route_file=filename,
                sink_kind="sql_execute", sink_file=filename, sink_line=sink_line,
                hops=0, files=[filename],
            )
        )
    (tmp_path / filename).write_text("\n".join(lines), encoding="utf-8")
    scan = ScanResult(root=str(tmp_path), routes=routes, taint_chains=chains)
    violations = [a for a in find_anomalies(scan, tmp_path) if a.kind == "invariant_violation"]
    assert len(violations) == 1
    assert violations[0].route_path == "/api/res9/<id>"


def test_invariant_survives_taint_fanout(tmp_path: Path) -> None:
    """The import walk fans a route out to every sink in its file, so a guarded
    handler also "reaches" foreign sinks in other handlers' bodies. Those
    foreign reaches must not mark the handler unguarded (regression): only the
    genuinely guard-less handler is flagged."""
    filename = "app.py"
    lines: list[str] = ["from flask import Flask", "app = Flask(__name__)", ""]
    routes: list[Route] = []
    sink_lines: dict[str, int] = {}
    for i in range(5):
        path = f"/api/res{i}/<id>"
        route_line = len(lines) + 1
        lines.append(f'@app.route("{path}")')
        lines.append(f"def handler{i}(id):")
        if i < 4:
            lines.append("    current_user.assert_can_read(id)")
        sink_line = len(lines) + 1
        lines.append('    return db.execute("SELECT * FROM t WHERE id=" + id)')
        lines.append("")
        routes.append(Route(path=path, method="GET", file=filename, line=route_line))
        sink_lines[path] = sink_line
    (tmp_path / filename).write_text("\n".join(lines), encoding="utf-8")
    # Fan-out: every route reaches every sink in the file (real taint shape).
    chains = [
        TaintChain(
            route_path=r.path, route_method="GET", route_file=filename,
            sink_kind="sql_execute", sink_file=filename, sink_line=sl, hops=0,
            files=[filename],
        )
        for r in routes
        for sl in sink_lines.values()
    ]
    scan = ScanResult(root=str(tmp_path), routes=routes, taint_chains=chains)
    violations = [a for a in find_anomalies(scan, tmp_path) if a.kind == "invariant_violation"]
    assert len(violations) == 1
    assert violations[0].route_path == "/api/res4/<id>"
    assert violations[0].consistent_peers == 4
