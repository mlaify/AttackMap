"""Tests for BOLA / IDOR detection (#69)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.authz import analyze_authz, _resource_id_param
from attackmap.models import BolaCandidate, DatabaseHint, Route, ScanResult, TaintChain
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_attack_paths, generate_findings


# ---------------------------------------------------------------------------
# ID-param detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/users/{id}", "id"),
        ("/users/{user_id}", "user_id"),
        ("/orders/:orderId", "orderId"),
        ("/docs/<int:doc_id>", "doc_id"),
        ("/items/<id>", "id"),
        ("/things/{uuid}", "uuid"),
        ("/posts/{slug}", "slug"),
        ("/api/{account_id}/settings", "account_id"),
    ],
)
def test_resource_id_param_detected(path: str, expected: str) -> None:
    assert _resource_id_param(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/health",
        "/users",
        "/reports/{format}",  # `format` is not id-shaped
        "/search/{query}",
        "/i18n/{lang}",
        "/static/{filename}",  # filename is a path, not a resource id we enumerate
    ],
)
def test_non_id_paths_not_detected(path: str) -> None:
    assert _resource_id_param(path) is None


# ---------------------------------------------------------------------------
# Candidate logic (controlled ScanResult + on-disk route file)
# ---------------------------------------------------------------------------


def _scan_with_route(tmp_path: Path, path: str, method: str, file_body: str, *, db_same_file=True) -> ScanResult:
    (tmp_path / "handler.py").write_text(file_body, encoding="utf-8")
    databases = [DatabaseHint(kind="postgres", file="handler.py")] if db_same_file else []
    return ScanResult(
        root=str(tmp_path),
        routes=[Route(path=path, method=method, file="handler.py")],
        databases=databases,
    )


def test_id_route_reaching_db_without_ownership_is_candidate(tmp_path: Path) -> None:
    scan = _scan_with_route(
        tmp_path,
        "/orders/{order_id}",
        "GET",
        "def get_order(order_id):\n    return db.execute('SELECT * FROM orders WHERE id=%s', order_id)\n",
    )
    candidates = analyze_authz(scan, tmp_path)
    assert len(candidates) == 1
    assert candidates[0].id_param == "order_id"
    assert candidates[0].reaches_db is True
    assert candidates[0].source_analyzer == "authz"


def test_ownership_check_suppresses_candidate(tmp_path: Path) -> None:
    scan = _scan_with_route(
        tmp_path,
        "/orders/{order_id}",
        "GET",
        "def get_order(order_id):\n"
        "    if order.owner_id != current_user.id:\n"
        "        abort(403)\n"
        "    return db.execute('SELECT * FROM orders WHERE id=%s', order_id)\n",
    )
    assert analyze_authz(scan, tmp_path) == []


@pytest.mark.parametrize(
    "marker_line",
    [
        "    require_permission('orders:read')\n",
        "    authorize(current_user, order)\n",
        "    if not policy.can_access(user, order): abort(403)\n",
        "    rows = Order.query.filter_by(user_id=g.user.id).all()\n",
    ],
)
def test_various_ownership_markers_suppress(tmp_path: Path, marker_line: str) -> None:
    body = f"def get_order(order_id):\n{marker_line}    return db.execute('SELECT 1', order_id)\n"
    scan = _scan_with_route(tmp_path, "/orders/{order_id}", "GET", body)
    assert analyze_authz(scan, tmp_path) == []


def test_id_route_without_db_is_not_candidate(tmp_path: Path) -> None:
    scan = _scan_with_route(
        tmp_path,
        "/orders/{order_id}",
        "GET",
        "def get_order(order_id):\n    return {'echo': order_id}\n",
        db_same_file=False,
    )
    assert analyze_authz(scan, tmp_path) == []


def test_non_id_route_is_not_candidate(tmp_path: Path) -> None:
    scan = _scan_with_route(
        tmp_path,
        "/orders",
        "GET",
        "def list_orders():\n    return db.execute('SELECT * FROM orders')\n",
    )
    assert analyze_authz(scan, tmp_path) == []


def test_taint_sql_chain_provides_db_reachability(tmp_path: Path) -> None:
    """When there's no same-file DB hint but a taint chain reaches a SQL
    sink from the route, that counts as DB reachability."""
    (tmp_path / "handler.py").write_text(
        "def get_order(order_id):\n    return service.load(order_id)\n", encoding="utf-8"
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/orders/{order_id}", method="GET", file="handler.py")],
        taint_chains=[
            TaintChain(
                route_path="/orders/{order_id}",
                route_method="GET",
                route_file="handler.py",
                sink_kind="sql_execute",
                sink_file="db/orders.py",
                sink_line=10,
                hops=2,
                files=["handler.py", "service.py", "db/orders.py"],
            )
        ],
    )
    candidates = analyze_authz(scan, tmp_path)
    assert len(candidates) == 1
    assert "taint chain" in candidates[0].db_evidence


# ---------------------------------------------------------------------------
# Findings + severity split
# ---------------------------------------------------------------------------


def _bola(method: str, path: str = "/orders/{order_id}") -> BolaCandidate:
    return BolaCandidate(
        route_path=path,
        route_method=method,
        route_file="handler.py",
        id_param="order_id",
        reaches_db=True,
        db_evidence="datastore hint in the route's file",
    )


def test_write_candidate_produces_high_finding() -> None:
    scan = ScanResult(root="/", authz_candidates=[_bola("PUT")])
    findings = [f for f in generate_findings(scan) if "broken-authorization" in f.tags]
    assert findings
    assert findings[0].severity == "high"
    assert "modify" in findings[0].title
    assert findings[0].attack_techniques[0].technique_id == "T1190"


def test_read_candidate_produces_medium_finding() -> None:
    scan = ScanResult(root="/", authz_candidates=[_bola("GET")])
    findings = [f for f in generate_findings(scan) if "broken-authorization" in f.tags]
    assert findings
    assert findings[0].severity == "medium"
    assert "read" in findings[0].title


def test_mixed_methods_yield_two_findings_with_split_severity() -> None:
    scan = ScanResult(root="/", authz_candidates=[_bola("GET"), _bola("DELETE", "/orders/{oid}")])
    findings = [f for f in generate_findings(scan) if "broken-authorization" in f.tags]
    sevs = {f.severity for f in findings}
    assert sevs == {"high", "medium"}


def test_bola_attack_path_emitted() -> None:
    scan = ScanResult(root="/", authz_candidates=[_bola("DELETE")])
    paths = generate_attack_paths(scan)
    bola_paths = [p for p in paths if "BOLA" in p.name or "IDOR" in p.name]
    assert bola_paths
    assert "order_id" in " ".join(bola_paths[0].steps)


# ---------------------------------------------------------------------------
# End-to-end via scan_repo
# ---------------------------------------------------------------------------


def test_scan_repo_flags_bola_route(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/orders/<int:order_id>', methods=['GET'])\n"
        "def get_order(order_id):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute('SELECT * FROM orders WHERE id = %s', (order_id,))\n"
        "    return cur.fetchone()\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert scan.authz_candidates
    c = scan.authz_candidates[0]
    assert c.id_param == "order_id"
    assert c.route_method == "GET"


def test_scan_repo_respects_ownership_check(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "from flask_login import current_user\n"
        "app = Flask(__name__)\n"
        "@app.route('/orders/<int:order_id>', methods=['GET'])\n"
        "def get_order(order_id):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute('SELECT * FROM orders WHERE id = %s AND owner_id = %s', (order_id, current_user.id))\n"
        "    return cur.fetchone()\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert scan.authz_candidates == []


# ---------------------------------------------------------------------------
# #139: query-parameter & RPC-method & GraphQL scoping
# ---------------------------------------------------------------------------


def test_xrpc_id_bearing_method_flagged(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "def get_record(uri):\n    return db.query(uri)\n", encoding="utf-8"
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/xrpc/com.atproto.repo.getRecord", method="ANY", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    cands = analyze_authz(scan, tmp_path)
    assert len(cands) == 1
    assert cands[0].surface == "rpc_method"
    assert cands[0].id_param == "com.atproto.repo.getRecord"


def test_xrpc_non_object_method_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text("def x():\n    return db.query('x')\n", encoding="utf-8")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    assert analyze_authz(scan, tmp_path) == []


def test_query_param_id_flagged(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text("def x():\n    return db.query('x')\n", encoding="utf-8")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/api/orders?orderId=5", method="GET", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    cands = analyze_authz(scan, tmp_path)
    assert len(cands) == 1
    assert cands[0].surface == "query_param"
    assert cands[0].id_param == "orderId"


def test_query_param_non_id_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text("def x():\n    return db.query('x')\n", encoding="utf-8")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/api/orders?page=2&sort=asc", method="GET", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    assert analyze_authz(scan, tmp_path) == []


def test_rpc_ownership_check_suppresses(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "def get_record(uri):\n"
        "    if uri.owner_id != current_user.id:\n"
        "        raise Forbidden()\n"
        "    return db.query(uri)\n",
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/xrpc/com.atproto.repo.getRecord", method="ANY", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    assert analyze_authz(scan, tmp_path) == []


def test_graphql_id_field_flagged(tmp_path: Path) -> None:
    (tmp_path / "schema.graphql").write_text(
        "type Query {\n"
        "  user(id: ID!): User\n"
        "  feed(limit: Int): [Post]\n"
        "}\n"
        "type Mutation {\n"
        "  deleteOrder(orderId: String!): Boolean\n"
        "}\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[])
    cands = analyze_authz(scan, tmp_path)
    by_field = {c.route_path: c for c in cands}
    assert "graphql:user" in by_field
    assert by_field["graphql:user"].surface == "graphql_field"
    assert by_field["graphql:user"].route_method == "QUERY"
    assert "graphql:deleteOrder" in by_field
    assert by_field["graphql:deleteOrder"].route_method == "MUTATION"
    # A field with no id argument is not an object reference.
    assert "graphql:feed" not in by_field


def test_graphql_auth_directive_suppresses(tmp_path: Path) -> None:
    (tmp_path / "schema.graphql").write_text(
        "type Query {\n"
        "  account(id: ID!): Account @auth\n"
        "  secret(id: ID!): Secret @hasRole(role: ADMIN)\n"
        "}\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[])
    assert analyze_authz(scan, tmp_path) == []


def test_graphql_inline_sdl_in_code_scanned(tmp_path: Path) -> None:
    (tmp_path / "schema.ts").write_text(
        "export const typeDefs = gql`\n"
        "  type Query {\n"
        "    document(docId: ID!): Document\n"
        "  }\n"
        "`;\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[])
    cands = analyze_authz(scan, tmp_path)
    assert any(c.route_path == "graphql:document" for c in cands)


def test_bola_finding_evidence_cites_surface(tmp_path: Path) -> None:
    scan = ScanResult(
        root=str(tmp_path),
        authz_candidates=[
            BolaCandidate(
                route_path="/xrpc/com.atproto.repo.getRecord",
                route_method="ANY",
                route_file="h.py",
                id_param="com.atproto.repo.getRecord",
                surface="rpc_method",
                reaches_db=True,
                db_evidence="RPC object-access method",
            )
        ],
    )
    findings = [f for f in generate_findings(scan) if "broken-authorization" in f.tags]
    assert findings
    joined = "\n".join(findings[0].evidence)
    assert "RPC method" in joined
    assert "com.atproto.repo.getRecord" in joined
