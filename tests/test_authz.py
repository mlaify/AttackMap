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
        ("/orders/<int:pk>/", "pk"),
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


def test_query_param_id_read_in_handler_flagged(tmp_path: Path) -> None:
    # The id arrives as a query parameter read in the handler body (#139).
    (tmp_path / "handler.py").write_text(
        "def get_orders():\n"
        "    oid = request.args.get('orderId')\n"
        "    return db.query('SELECT * FROM orders WHERE id=' + oid)\n",
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/api/orders", method="GET", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    cands = analyze_authz(scan, tmp_path)
    assert len(cands) == 1
    assert cands[0].surface == "query_param"
    assert cands[0].id_param == "orderId"


def test_query_param_fastapi_signature_flagged(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "def read_doc(docId: str = Query(...)):\n    return db.query(docId)\n",
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/api/docs", method="GET", file="handler.py")],
        databases=[DatabaseHint(kind="sqlite", file="handler.py")],
    )
    cands = analyze_authz(scan, tmp_path)
    assert len(cands) == 1
    assert cands[0].id_param == "docId"


def test_query_param_non_id_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "def x():\n    page = request.args.get('page')\n    return db.query('x')\n",
        encoding="utf-8",
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/api/orders", method="GET", file="handler.py")],
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


def test_graphql_test_fixture_schema_excluded(tmp_path: Path) -> None:
    """SDL under a test/fixture path is a low-quality source — not flagged."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "schema.graphql").write_text(
        "type Query {\n  user(id: ID!): User\n}\n", encoding="utf-8"
    )
    scan = ScanResult(root=str(tmp_path), routes=[])
    assert analyze_authz(scan, tmp_path) == []


def test_graphql_resolver_ownership_suppresses(tmp_path: Path) -> None:
    """A field with no SDL directive but whose resolver enforces ownership is
    not a candidate (#139 — resolver-level auth)."""
    (tmp_path / "schema.graphql").write_text(
        "type Query {\n  document(id: ID!): Document\n}\n", encoding="utf-8"
    )
    (tmp_path / "resolvers.ts").write_text(
        "export const resolvers = {\n"
        "  Query: {\n"
        "    document: (parent, { id }, ctx) => {\n"
        "      if (!ctx.current_user) throw new Error('unauthorized');\n"
        "      return db.documents.find(id, ctx.current_user.id);\n"
        "    },\n"
        "  },\n"
        "};\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[])
    assert analyze_authz(scan, tmp_path) == []


def test_graphql_custom_root_operation_types(tmp_path: Path) -> None:
    """Custom root types declared via `schema { query: RootQuery }` are scanned."""
    (tmp_path / "schema.graphql").write_text(
        "schema {\n  query: RootQuery\n  mutation: RootMutation\n}\n"
        "type RootQuery {\n  account(id: ID!): Account\n}\n"
        "type RootMutation {\n  deleteAccount(id: ID!): Boolean\n}\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[])
    cands = analyze_authz(scan, tmp_path)
    by_field = {c.route_path: c for c in cands}
    assert by_field["graphql:account"].route_method == "QUERY"
    assert by_field["graphql:deleteAccount"].route_method == "MUTATION"


def test_graphql_mutation_narrated_as_write_in_attack_path(tmp_path: Path) -> None:
    """A GraphQL mutation BOLA candidate is a write, not a read, in attack paths."""
    scan = ScanResult(
        root=str(tmp_path),
        authz_candidates=[
            BolaCandidate(
                route_path="graphql:deleteAccount",
                route_method="MUTATION",
                route_file="schema.graphql",
                id_param="id",
                surface="graphql_field",
                reaches_db=True,
                db_evidence="GraphQL mutation field resolves an object by `id`",
            )
        ],
    )
    paths = [p for p in generate_attack_paths(scan) if "BOLA" in p.name or "IDOR" in p.name]
    assert paths
    assert "modify" in " ".join(paths[0].steps).lower()


# ---------------------------------------------------------------------------
# Authorization depth (#242): authn ≠ authz, handler scope, one hop, BFLA
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "authz"


def _bola_findings(scan: ScanResult):
    return [f for f in generate_findings(scan) if "broken-authorization" in f.tags]


def _bfla_findings(scan: ScanResult):
    return [f for f in generate_findings(scan) if f.rule_id == "bfla-privileged-route"]


@pytest.mark.parametrize(
    ("fixture", "route"),
    [
        ("express_router_use_auth_idor", "/invoices/:id"),
        ("flask_login_required_idor", "/orders/<int:order_id>"),
    ],
)
def test_authenticated_idor_fixture_flagged_high(fixture: str, route: str) -> None:
    # Authentication (router.use(requireAuth), @login_required, req.user /
    # current_user references) no longer hides the missing object check.
    scan = scan_repo(FIXTURES / fixture)
    cands = [c for c in scan.authz_candidates if c.route_path == route]
    assert len(cands) == 1
    assert cands[0].confidence == "high"
    assert cands[0].authn_evidence
    findings = _bola_findings(scan)
    assert findings and findings[0].confidence == "high"
    assert "no object-level check" in findings[0].evidence[0]


def test_mixed_file_flags_only_the_unscoped_handler() -> None:
    scan = scan_repo(FIXTURES / "mixed_scoped_unscoped")
    assert [c.route_path for c in scan.authz_candidates] == ["/receipts/:id"]


def _plugin_shaped_scan(root: Path, route: Route) -> ScanResult:
    # Django / Spring routes come from the plugins; reproduce the shape they
    # emit (file + declaration line) with a datastore hint in that file.
    return ScanResult(
        root=str(root), routes=[route], databases=[DatabaseHint(kind="sql", file=route.file)]
    )


def test_django_scoped_view_is_clean_one_hop_from_urlconf() -> None:
    root = FIXTURES / "django_scoped_ok"
    route = Route(path="/orders/<int:pk>/", method="ANY", file="orders/urls.py", line=6)
    assert analyze_authz(_plugin_shaped_scan(root, route), root) == []


def test_django_unscoped_view_flagged_through_the_hop(tmp_path: Path) -> None:
    # Negative control for the fixture above: same URLconf, unscoped view.
    pkg = tmp_path / "orders"
    pkg.mkdir()
    (pkg / "urls.py").write_text((FIXTURES / "django_scoped_ok/orders/urls.py").read_text())
    (pkg / "views.py").write_text(
        "from django.contrib.auth.decorators import login_required\n"
        "@login_required\n"
        "def order_detail(request, pk):\n"
        "    return JsonResponse({'id': Order.objects.get(pk=pk).pk})\n"
    )
    route = Route(path="/orders/<int:pk>/", method="ANY", file="orders/urls.py", line=6)
    cands = analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path)
    assert [c.id_param for c in cands] == ["pk"]


def test_spring_preauthorize_owner_expression_is_clean() -> None:
    root = FIXTURES / "spring_preauthorize_ok"
    route = Route(
        path="/api/orders/{id}",
        method="GET",
        file="src/main/java/com/example/orders/OrderController.java",
        line=20,
    )
    assert analyze_authz(_plugin_shaped_scan(root, route), root) == []


def test_spring_without_preauthorize_flagged(tmp_path: Path) -> None:
    src = (FIXTURES / "spring_preauthorize_ok/src/main/java/com/example/orders/OrderController.java").read_text()
    stripped = "\n".join(line for line in src.splitlines() if "@PreAuthorize(" not in line)
    (tmp_path / "OrderController.java").write_text(stripped)
    line = next(i for i, ln in enumerate(stripped.splitlines(), 1) if "@GetMapping" in ln)
    route = Route(path="/api/orders/{id}", method="GET", file="OrderController.java", line=line)
    assert len(analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path)) == 1


def test_sibling_handler_markers_do_not_suppress(tmp_path: Path) -> None:
    # The flask-admin-demo shape: a `user_id: str` annotation in a *different*
    # handler used to suppress the whole file.
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/orders/<order_id>')\n"
        "def get_order(order_id):\n"
        "    sqlite3.connect('o.db').execute('select * from orders where id = ?', (order_id,))\n"
        "@app.route('/users/<user_id>')\n"
        "def get_user(user_id: str):\n"
        "    if user.owner_id != current_user.id: abort(403)\n"
        "    sqlite3.connect('o.db').execute('select * from users where id = ?', (user_id,))\n"
    )
    scan = scan_repo(tmp_path)
    assert [c.route_path for c in scan.authz_candidates] == ["/orders/<order_id>"]
    assert scan.authz_candidates[0].confidence == "medium"  # no authentication either


def test_ownership_check_in_imported_service_is_followed(tmp_path: Path) -> None:
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "invoices.py").write_text(
        "def load_invoice(invoice_id, user):\n"
        "    return Invoice.query.filter_by(id=invoice_id, owner_id=user.id).first()\n"
    )
    (tmp_path / "app.py").write_text(
        "from services import invoices as svc\n"
        "@app.get('/invoices/{invoice_id}')\n"
        "def get_invoice(invoice_id, user=Depends(get_current_user)):\n"
        "    return svc.load_invoice(invoice_id, user)\n"
    )
    route = Route(path="/invoices/{invoice_id}", method="GET", file="app.py", line=2)
    assert analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path) == []


def test_js_handler_reference_resolved_in_controller_module(tmp_path: Path) -> None:
    (tmp_path / "controllers").mkdir()
    (tmp_path / "controllers" / "docs.js").write_text(
        "exports.getDoc = async (req, res) => {\n"
        "  const doc = await Doc.findOne({ _id: req.params.id, ownerId: req.user.id });\n"
        "  res.json(doc);\n"
        "};\n"
        "exports.getNote = async (req, res) => {\n"
        "  res.json(await Note.findById(req.params.id));\n"
        "};\n"
    )
    (tmp_path / "routes.js").write_text(
        "const ctrl = require('./controllers/docs');\n"
        "router.get('/docs/:id', requireAuth, ctrl.getDoc);\n"
        "router.get('/notes/:id', requireAuth, ctrl.getNote);\n"
    )
    scan = ScanResult(
        root=str(tmp_path),
        routes=[
            Route(path="/docs/:id", method="GET", file="routes.js", line=2),
            Route(path="/notes/:id", method="GET", file="routes.js", line=3),
        ],
        databases=[DatabaseHint(kind="mongodb", file="routes.js")],
    )
    cands = analyze_authz(scan, tmp_path)
    assert [c.route_path for c in cands] == ["/notes/:id"]
    assert cands[0].confidence == "high"


def test_hop_never_leaves_the_repo(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("def load(i):\n    return X.filter_by(owner_id=current_user.id)\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from ..outside import load\n"
        "@app.get('/things/{thing_id}')\n"
        "def get_thing(thing_id):\n"
        "    return load(thing_id)\n"
    )
    route = Route(path="/things/{thing_id}", method="GET", file="app.py", line=2)
    assert len(analyze_authz(_plugin_shaped_scan(repo, route), repo)) == 1


def test_fastapi_current_user_dependency_is_authn_not_authz(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.get('/orders/{order_id}')\n"
        "def get_order(order_id: int, user=Depends(get_current_user)):\n"
        "    return db.execute('select * from orders where id = %s', (order_id,))\n"
    )
    route = Route(path="/orders/{order_id}", method="GET", file="app.py", line=1)
    cands = analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path)
    assert len(cands) == 1 and cands[0].confidence == "high"


def test_role_gated_route_is_not_bola(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.route('/admin/users/<user_id>', methods=['DELETE'])\n"
        "@roles_required('admin')\n"
        "def delete_user(user_id):\n"
        "    db.execute('delete from users where id = ?', (user_id,))\n"
    )
    route = Route(path="/admin/users/<user_id>", method="DELETE", file="app.py", line=1)
    assert analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path) == []


def test_bfla_fixture_flags_only_the_route_without_role_check() -> None:
    scan = scan_repo(FIXTURES / "bfla_require_auth")
    findings = _bfla_findings(scan)
    assert len(findings) == 1
    assert len(findings[0].evidence) == 1
    assert "DELETE /admin/users/:id" in findings[0].evidence[0]
    assert findings[0].taxonomy is not None and "CWE-285" in findings[0].taxonomy.cwe


def test_bfla_needs_authentication(tmp_path: Path) -> None:
    # No authn at all is the unauthenticated-route finding's job, not BFLA.
    (tmp_path / "server.js").write_text(
        "const app = require('express')();\n"
        "app.delete('/admin/users/:id', async (req, res) => { await User.remove(req.params.id); });\n"
    )
    scan = scan_repo(tmp_path)
    assert _bfla_findings(scan) == []
    assert any(f.rule_id == "unauth-state-change" for f in generate_findings(scan))


def test_bfla_respects_declared_role_guard(tmp_path: Path) -> None:
    (tmp_path / "Admin.cs").write_text("// handled by a plugin\n")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[
            Route(
                path="/admin/users/{id}", method="DELETE", file="Admin.cs", line=1,
                auth="required", guards=["[Authorize(Roles = \"Admin\")]", "hasRole('ADMIN')"],
            )
        ],
    )
    assert _bfla_findings(scan) == []


def test_bfla_respects_hummingbird_role_and_permission_policies(tmp_path: Path) -> None:
    # Hummingbird's AuthorizationPolicyMiddleware(RolePolicy(...)) gates the route
    # on a role, as reported by the Swift plugin (#187).
    (tmp_path / "Admin.swift").write_text("// handled by a plugin\n")
    routes = [
        Route(
            path="/admin/users", method="GET", file="Admin.swift", line=1, auth="required",
            guards=["BasicAuthenticator", f"AuthorizationPolicyMiddleware({policy}(.admin))"],
        )
        for policy in ("RolePolicy", "PermissionPolicy")
    ]
    for route in routes:
        assert _bfla_findings(ScanResult(root=str(tmp_path), routes=[route])) == []
    unguarded = Route(path="/admin/users", method="GET", file="Admin.swift", line=1, auth="required",
                      guards=["BasicAuthenticator"])
    assert len(_bfla_findings(ScanResult(root=str(tmp_path), routes=[unguarded]))) == 1


def test_unauthenticated_write_reported_once_not_as_bola(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/orders/<order_id>/cancel', methods=['POST'])\n"
        "def cancel(order_id):\n"
        "    sqlite3.connect('o.db').execute('update orders set s = 1 where id = ?', (order_id,))\n"
    )
    scan = scan_repo(tmp_path)
    assert scan.authz_candidates  # still recorded for downstream consumers
    assert _bola_findings(scan) == []
    assert any(f.rule_id == "unauth-state-change" for f in generate_findings(scan))


def test_one_bola_attack_path_per_file_bounded() -> None:
    cands = [
        BolaCandidate(
            route_path=f"/things/{{thing_id}}/{i}", route_method="GET", route_file=f"svc{i}.py",
            id_param="thing_id", reaches_db=True, db_evidence="datastore hint in the route's file",
        )
        for i in range(6)
    ]
    cands.append(cands[0].model_copy(update={"route_path": "/other/{thing_id}"}))
    paths = [p for p in generate_attack_paths(ScanResult(root="/", authz_candidates=cands)) if "BOLA" in p.name]
    files = [next(f"svc{i}.py" for i in range(6) if f"svc{i}.py" in " ".join(p.steps)) for p in paths]
    assert len(paths) == 3
    assert len(set(files)) == 3


def test_hop_ignores_a_bare_model_mention(tmp_path: Path) -> None:
    # `Order.query…` mentions the model; it doesn't delegate to it, so an
    # `is_owner` helper on the model (never called here) must not suppress.
    (tmp_path / "app.py").write_text(
        "class Order(db.Model):\n"
        "    def is_owner(self, user):\n"
        "        return self.owner_id == user.id\n"
        "\n"
        "@app.get('/orders/{order_id}')\n"
        "def get_order(order_id):\n"
        "    return Order.query.get(order_id)\n"
    )
    route = Route(path="/orders/{order_id}", method="GET", file="app.py", line=5)
    assert len(analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path)) == 1


def test_braceless_arrow_definition_is_one_line(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "const load = (id) => Doc.findById(id);\n"
        "const unrelated = 1;\n"
        "function other(req) { return Doc.findOne({ ownerId: req.user.id }); }\n"
        "router.get('/docs/:id', requireAuth, async (req, res) => res.json(await load(req.params.id)));\n"
    )
    route = Route(path="/docs/:id", method="GET", file="routes.js", line=4)
    assert len(analyze_authz(_plugin_shaped_scan(tmp_path, route), tmp_path)) == 1


def test_bola_attack_path_wording_follows_authn() -> None:
    anon = _bola("GET")
    authed = _bola("GET", "/x/{order_id}").model_copy(
        update={"route_file": "other.py", "authn_evidence": "auth decorator", "confidence": "high"}
    )
    paths = [p for p in generate_attack_paths(ScanResult(root="/", authz_candidates=[anon, authed])) if "BOLA" in p.name]
    entries = sorted(p.steps[0] for p in paths)
    assert any("An authenticated attacker" in e for e in entries)
    assert any("An attacker calls" in e for e in entries)


def test_bola_in_example_or_fixture_paths_not_reported() -> None:
    cand = _bola("GET").model_copy(update={"route_file": "examples/demo/app.py"})
    scan = ScanResult(root="/", authz_candidates=[cand])
    assert _bola_findings(scan) == []
    assert not [p for p in generate_attack_paths(scan) if "BOLA" in p.name]
