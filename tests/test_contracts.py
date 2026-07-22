"""Tests for cross-repo contract linking (#146b)."""

from __future__ import annotations

from attackmap.contracts import ContractLink, link_contracts
from attackmap.models import ExternalCall, Route, ScanResult


def _scan(root: str, *, routes=None, calls=None) -> ScanResult:
    return ScanResult(root=root, routes=list(routes or []), external_calls=list(calls or []))


def _client(root: str, target: str, method: str | None = "GET") -> ScanResult:
    return _scan(root, calls=[ExternalCall(target=target, method=method, file="c.py", line=3)])


def _server(root: str, path: str, method: str = "GET") -> ScanResult:
    return _scan(root, routes=[Route(path=path, method=method, file="s.py", line=5)])


# ---------------------------------------------------------------------------
# core matching
# ---------------------------------------------------------------------------


def test_links_concatenated_client_url_to_templated_route() -> None:
    # requests.get("http://svc/api/orders/" + oid) — captured up to trailing slash.
    links = link_contracts(
        [
            ("client", _client("client", "http://order-svc/api/orders/")),
            ("server", _server("server", "/api/orders/<id>")),
        ]
    )
    assert len(links) == 1
    lk = links[0]
    assert lk.client_repo == "client" and lk.server_repo == "server"
    assert lk.method == "GET"
    assert lk.path_template == "api/orders/*"
    assert lk.server_route_path == "/api/orders/<id>"
    assert lk.client_line == 3 and lk.server_line == 5


def test_links_literal_id_to_template() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "https://b.internal/users/12345")),
            ("b", _server("b", "/users/{id}")),
        ]
    )
    assert len(links) == 1
    assert links[0].path_template == "users/*"


def test_collection_route_not_confused_with_detail() -> None:
    # No trailing slash → collection call; must NOT match the /{id} detail route.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/orders")),
            ("b", _server("b", "/api/orders/{id}")),
        ]
    )
    assert links == []


# ---------------------------------------------------------------------------
# method compatibility
# ---------------------------------------------------------------------------


def test_method_mismatch_does_not_link() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/items/1", method="POST")),
            ("b", _server("b", "/api/items/{id}", method="GET")),
        ]
    )
    assert links == []


def test_unknown_client_method_matches_any() -> None:
    # fetch(...) → method None → matches the route's method.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/items/1", method=None)),
            ("b", _server("b", "/api/items/{id}", method="DELETE")),
        ]
    )
    assert len(links) == 1
    assert links[0].method == "DELETE"


# ---------------------------------------------------------------------------
# precision guards
# ---------------------------------------------------------------------------


def test_no_self_links_within_one_repo() -> None:
    scan = _scan(
        "solo",
        routes=[Route(path="/api/orders/{id}", method="GET", file="s.py", line=1)],
        calls=[ExternalCall(target="http://solo/api/orders/9", method="GET", file="c.py", line=2)],
    )
    assert link_contracts([("solo", scan)]) == []


def test_infra_paths_excluded() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b/health")),
            ("b", _server("b", "/health")),
        ]
    )
    assert links == []


def test_all_variable_path_not_linked() -> None:
    # No static segment to anchor on → too generic.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/12345")),
            ("b", _server("b", "/{id}")),
        ]
    )
    assert links == []


def test_unrelated_paths_do_not_link() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/widgets/1")),
            ("b", _server("b", "/api/gadgets/{id}")),
        ]
    )
    assert links == []


def test_deterministic_and_deduped() -> None:
    a = _scan(
        "a",
        calls=[
            ExternalCall(target="http://b/api/orders/1", method="GET", file="c.py", line=1),
            ExternalCall(target="http://b/api/orders/2", method="GET", file="c.py", line=1),
        ],
    )
    b = _server("b", "/api/orders/{id}")
    links = link_contracts([("a", a), ("b", b)])
    # Same (client file/line, server route) collapses to one link.
    assert len(links) == 1
    assert isinstance(links[0], ContractLink)


# ---------------------------------------------------------------------------
# Codex review regressions (#146b)
# ---------------------------------------------------------------------------


def test_test_and_vendored_callers_excluded() -> None:
    # A call from a test/fixture or vendored file is not production architecture.
    for bad_file in ("tests/test_client.py", "vendor/lib/http.js"):
        client = ScanResult(
            root="a",
            external_calls=[ExternalCall(target="http://b/api/orders/1", method="GET", file=bad_file)],
        )
        server = _server("b", "/api/orders/{id}")
        assert link_contracts([("a", client), ("b", server)]) == [], bad_file


def test_two_verbs_same_target_survive_merge() -> None:
    # merge identity now includes method, so GET+POST /items don't collapse (#146b).
    from attackmap.analyzers import merge_analyzer_results

    r1 = ScanResult(
        root="a", external_calls=[ExternalCall(target="http://b/api/items/1", method="GET", file="c.py")]
    )
    r2 = ScanResult(
        root="a", external_calls=[ExternalCall(target="http://b/api/items/1", method="POST", file="c.py")]
    )
    merged = merge_analyzer_results([r1, r2], root="a")
    methods = {c.method for c in merged.external_calls if c.target == "http://b/api/items/1"}
    assert methods == {"GET", "POST"}


def test_bare_fetch_defaults_to_get_and_parses_init_method(tmp_path) -> None:
    from attackmap.scanner import scan_repo

    (tmp_path / "client.js").write_text(
        'fetch("http://b/api/items/1");\n'
        'fetch("http://b/api/items/2", { method: "POST" });\n',
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    by_target = {c.target: c.method for c in scan.external_calls}
    assert by_target.get("http://b/api/items/1") == "GET"
    assert by_target.get("http://b/api/items/2") == "POST"
