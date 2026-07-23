"""Tests for cross-boundary trust analysis (#146c)."""

from __future__ import annotations

from attackmap.contracts import ContractLink
from attackmap.crossrepo import (
    CrossBoundaryFlow,
    find_cross_boundary_flows,
    find_cross_repo_anomalies,
    find_trust_gaps,
)
from attackmap.models import BolaCandidate, Route, ScanResult, TaintChain


def _link(route: str = "/api/orders/<id>", method: str = "GET") -> ContractLink:
    return ContractLink(
        client_repo="client",
        server_repo="server",
        method=method,
        path_template="api/orders/*",
        client_target="http://order-svc/api/orders/",
        client_file="c.py",
        client_line=4,
        server_route_path=route,
        server_file="s.py",
        server_line=5,
    )


def _taint_chain(route: str, sink: str = "sql_execute", **kw) -> TaintChain:
    return TaintChain(
        route_path=route,
        route_method=kw.get("route_method", "GET"),
        route_file="s.py",
        sink_kind=sink,
        sink_file=kw.get("sink_file", "db.py"),
        sink_line=kw.get("sink_line", 9),
        hops=kw.get("hops", 1),
        files=["s.py", "db.py"],
        sanitized=kw.get("sanitized", False),
    )


def _bola(route: str, **kw) -> BolaCandidate:
    return BolaCandidate(
        route_path=route,
        route_method=kw.get("route_method", "GET"),
        route_file="s.py",
        route_line=5,
        id_param="id",
        reaches_db=kw.get("reaches_db", True),
        has_ownership_check=kw.get("has_ownership_check", False),
    )


# ---------------------------------------------------------------------------
# taint basis
# ---------------------------------------------------------------------------


def test_taint_basis_flow_cites_both_sides() -> None:
    server = ScanResult(root="server", taint_chains=[_taint_chain("/api/orders/<id>")])
    flows = find_cross_boundary_flows([_link()], [("client", ScanResult(root="client")), ("server", server)])
    assert len(flows) == 1
    f = flows[0]
    assert f.basis == "taint" and f.detail == "sql_execute"
    assert f.client_repo == "client" and f.server_repo == "server"
    assert f.client_file == "c.py" and f.client_line == 4  # caller cited
    assert f.server_file == "db.py" and f.server_line == 9  # callee sink cited
    assert f.severity == "high"


def test_sanitized_sink_does_not_flow() -> None:
    server = ScanResult(root="server", taint_chains=[_taint_chain("/api/orders/<id>", sanitized=True)])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    assert flows == []


def test_non_dangerous_sink_does_not_flow() -> None:
    server = ScanResult(root="server", taint_chains=[_taint_chain("/api/orders/<id>", sink="open_redirect")])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    # open_redirect isn't in the cross-boundary dangerous set.
    assert flows == []


# ---------------------------------------------------------------------------
# bola basis
# ---------------------------------------------------------------------------


def test_bola_basis_flow() -> None:
    server = ScanResult(root="server", authz_candidates=[_bola("/api/orders/<id>")])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    assert len(flows) == 1
    assert flows[0].basis == "bola"
    assert "id" in flows[0].detail


def test_bola_with_ownership_check_does_not_flow() -> None:
    server = ScanResult(root="server", authz_candidates=[_bola("/api/orders/<id>", has_ownership_check=True)])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    assert flows == []


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------


def test_no_flow_when_route_is_defended() -> None:
    # Linked route serves nothing dangerous — no cross-boundary risk.
    server = ScanResult(root="server", taint_chains=[_taint_chain("/other/route")])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    assert flows == []


def test_no_flow_without_links() -> None:
    server = ScanResult(root="server", taint_chains=[_taint_chain("/api/orders/<id>")])
    assert find_cross_boundary_flows([], [("server", server)]) == []


def test_method_must_match_route_signal() -> None:
    # Link is POST, the dangerous chain is on the GET handler → no flow.
    server = ScanResult(
        root="server", taint_chains=[_taint_chain("/api/orders/<id>", route_method="GET")]
    )
    flows = find_cross_boundary_flows(
        [_link(method="POST")], [("server", server)]
    )
    assert flows == []


def test_deduped_per_basis() -> None:
    server = ScanResult(
        root="server",
        taint_chains=[
            _taint_chain("/api/orders/<id>", sink_line=9),
            _taint_chain("/api/orders/<id>", sink_line=20),
        ],
    )
    flows = find_cross_boundary_flows([_link(), _link()], [("server", server)])
    assert len(flows) == 1
    assert isinstance(flows[0], CrossBoundaryFlow)


# ---------------------------------------------------------------------------
# Codex review regressions (#146c)
# ---------------------------------------------------------------------------


def _static_link(route: str) -> ContractLink:
    # A fully-static collection call — no dynamic path segment forwarded.
    return ContractLink(
        client_repo="client", server_repo="server", method="GET",
        path_template="orders", client_target="http://svc/orders",
        client_file="c.py", client_line=4, server_route_path=route,
        server_file="s.py", server_line=5,
    )


def test_static_call_not_a_confused_deputy() -> None:
    # Client forwards no per-request value; a server-side taint on the same
    # route is not evidence the caller's value reaches it (P1).
    server = ScanResult(root="server", taint_chains=[_taint_chain("/orders")])
    assert find_cross_boundary_flows([_static_link("/orders")], [("server", server)]) == []


def test_query_param_bola_surface_excluded() -> None:
    # A query-param object id can't be tied to the matched path template (P1).
    server = ScanResult(
        root="server",
        authz_candidates=[_bola("/api/orders/<id>")],
    )
    server.authz_candidates[0].surface = "query_param"
    assert find_cross_boundary_flows([_link()], [("server", server)]) == []


def test_taint_severity_derived_from_sink() -> None:
    server = ScanResult(root="server", taint_chains=[_taint_chain("/api/orders/<id>", sink="ssrf")])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    assert flows[0].severity == "medium"  # ssrf is medium, not hard-coded high


def test_recall_speculative_chain_downgrades_severity() -> None:
    chain = _taint_chain("/api/orders/<id>", sink="sql_execute")
    chain.speculative = True
    server = ScanResult(root="server", taint_chains=[chain])
    flows = find_cross_boundary_flows([_link()], [("server", server)])
    assert flows[0].severity == "medium"  # high sink docked one notch for recall


def test_read_only_bola_is_medium_state_changing_is_high() -> None:
    server = ScanResult(root="server", authz_candidates=[_bola("/api/orders/<id>")])
    get_flows = find_cross_boundary_flows([_link(method="GET")], [("server", server)])
    assert get_flows[0].severity == "medium"
    del_flows = find_cross_boundary_flows(
        [_link(method="DELETE")],
        [("server", ScanResult(root="server", authz_candidates=[_bola("/api/orders/<id>", route_method="DELETE")]))],
    )
    assert del_flows[0].severity == "high"


# ---------------------------------------------------------------------------
# trust-assumption gap (#146d)
# ---------------------------------------------------------------------------


def _route(path: str, method: str, file: str = "s.py", line: int = 5) -> Route:
    return Route(path=path, method=method, file=file, line=line)


def test_trust_gap_unauthed_write_across_boundary() -> None:
    link = _link(route="/api/orders/<id>", method="POST")
    server = ScanResult(root="server", routes=[_route("/api/orders/<id>", "POST")])
    auth = {"server": {("s.py", "POST", "/api/orders/<id>"): False}}
    gaps = find_trust_gaps([link], [("client", ScanResult(root="client")), ("server", server)], auth)
    assert len(gaps) == 1
    g = gaps[0]
    assert g.client_repo == "client" and g.server_repo == "server"
    assert g.method == "POST" and g.route == "/api/orders/<id>"
    assert g.client_file == "c.py" and g.server_file == "s.py"
    assert g.severity == "high"


def test_trust_gap_not_fired_when_route_authed() -> None:
    link = _link(route="/api/orders/<id>", method="POST")
    server = ScanResult(root="server", routes=[_route("/api/orders/<id>", "POST")])
    auth = {"server": {("s.py", "POST", "/api/orders/<id>"): True}}
    assert find_trust_gaps([link], [("server", server)], auth) == []


def test_trust_gap_read_only_route_excluded() -> None:
    # A public GET is commonly intentional — only state-changing writes count.
    link = _link(route="/api/orders/<id>", method="GET")
    server = ScanResult(root="server", routes=[_route("/api/orders/<id>", "GET")])
    auth = {"server": {("s.py", "GET", "/api/orders/<id>"): False}}
    assert find_trust_gaps([link], [("server", server)], auth) == []


def test_trust_gap_unknown_auth_defaults_safe() -> None:
    link = _link(route="/api/orders/<id>", method="POST")
    server = ScanResult(root="server", routes=[_route("/api/orders/<id>", "POST")])
    assert find_trust_gaps([link], [("server", server)], {"server": {}}) == []


# ---------------------------------------------------------------------------
# cross-repo anomaly / #149b
# ---------------------------------------------------------------------------


def _repo_serving(repo: str, path: str, authed: bool):
    scan = ScanResult(root=repo, routes=[_route(path, "GET", file="app.py", line=1)])
    auth = {(("app.py", "GET", path)): authed}
    return (repo, scan), auth


def test_cross_repo_anomaly_flags_the_odd_service() -> None:
    r1, a1 = _repo_serving("svc-a", "/users/{id}", True)
    r2, a2 = _repo_serving("svc-b", "/users/{id}", True)
    r3, a3 = _repo_serving("svc-c", "/users/{id}", False)
    auth = {"svc-a": a1, "svc-b": a2, "svc-c": a3}
    anomalies = find_cross_repo_anomalies([r1, r2, r3], auth)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.repo == "svc-c"
    assert a.template == "users/*"
    assert set(a.peers) == {"svc-a", "svc-b"}


def test_cross_repo_anomaly_needs_three_services() -> None:
    r1, a1 = _repo_serving("svc-a", "/users/{id}", True)
    r2, a2 = _repo_serving("svc-b", "/users/{id}", False)
    auth = {"svc-a": a1, "svc-b": a2}
    assert find_cross_repo_anomalies([r1, r2], auth) == []


def test_cross_repo_anomaly_split_cohort_not_flagged() -> None:
    # 2 enforce / 2 omit is not a strong-majority norm.
    repos, auth = [], {}
    for name, authed in [("a", True), ("b", True), ("c", False), ("d", False)]:
        r, am = _repo_serving(name, "/users/{id}", authed)
        repos.append(r)
        auth[name] = am
    assert find_cross_repo_anomalies(repos, auth) == []


def test_cross_repo_anomaly_all_consistent_no_flag() -> None:
    repos, auth = [], {}
    for name in ("a", "b", "c"):
        r, am = _repo_serving(name, "/users/{id}", True)
        repos.append(r)
        auth[name] = am
    assert find_cross_repo_anomalies(repos, auth) == []
