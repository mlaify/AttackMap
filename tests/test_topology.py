"""Tests for service topology + trust-boundary graph (#18)."""

from __future__ import annotations

from attackmap.models import AuthHint, EdgeHint, ExternalCall, Route, ScanResult, ServiceHint
from attackmap.topology import ServiceEdge, ServiceGraph, ServiceNode, build_service_graph


# ---------------------------------------------------------------------------
# Node discovery
# ---------------------------------------------------------------------------


def test_empty_scan_yields_empty_graph() -> None:
    graph = build_service_graph(ScanResult(root="."))
    assert graph.nodes == []
    assert graph.edges == []


def test_service_name_hints_become_nodes() -> None:
    scan = ScanResult(
        root=".",
        service_hints=[
            ServiceHint(hint="service_name:api", file="services/api/src/server.ts"),
            ServiceHint(hint="service_name:worker", file="services/worker/src/index.ts"),
        ],
    )
    graph = build_service_graph(scan)
    names = graph.node_names()
    assert "api" in names
    assert "worker" in names


def test_repository_layout_falls_back_to_directory_name_as_service() -> None:
    """Files under services/*, packages/*, or apps/* imply a node even
    without an explicit service_name hint."""
    scan = ScanResult(
        root=".",
        routes=[Route(path="/ping", method="GET", file="services/gateway/src/http.ts")],
    )
    graph = build_service_graph(scan)
    assert graph.has_node("gateway")


def test_service_role_hints_annotate_the_matching_node() -> None:
    scan = ScanResult(
        root=".",
        service_hints=[
            ServiceHint(hint="service_name:api", file="services/api/src/server.ts"),
        ],
        auth_hints=[
            AuthHint(hint="service_role:api", file="services/api/src/server.ts"),
        ],
    )
    graph = build_service_graph(scan)
    api = next(n for n in graph.nodes if n.name == "api")
    assert api.role == "api"


# ---------------------------------------------------------------------------
# Edge discovery
# ---------------------------------------------------------------------------


def test_explicit_edge_hint_becomes_analyzer_declared_edge() -> None:
    scan = ScanResult(
        root=".",
        service_hints=[
            ServiceHint(hint="service_name:api", file="services/api/src/server.ts"),
            ServiceHint(hint="service_name:worker", file="services/worker/src/worker.ts"),
        ],
        edge_hints=[EdgeHint(hint="edge:api->worker", file="services/api/src/server.ts")],
    )
    graph = build_service_graph(scan)
    matches = [e for e in graph.edges if e.source == "api" and e.target == "worker"]
    assert len(matches) == 1
    assert matches[0].kind == "analyzer-declared"


def test_env_configured_url_pseudo_target_becomes_env_configured_edge() -> None:
    """`external_calls` carrying `env://FEEDGEN_URL` (emitted by
    node-service analyzer) turns into an env-configured edge to the
    peer `feedgen`."""
    scan = ScanResult(
        root=".",
        service_hints=[ServiceHint(hint="service_name:api", file="services/api/src/server.ts")],
        external_calls=[ExternalCall(target="env://FEEDGEN_URL", file="services/api/src/server.ts")],
    )
    graph = build_service_graph(scan)
    matches = [e for e in graph.edges if e.source == "api" and e.target == "feedgen"]
    assert len(matches) == 1
    assert matches[0].kind == "env-configured"


def test_direct_http_call_edge_uses_host_prefix_as_peer_name() -> None:
    """`https://worker.internal.local/rebuild` from api → edge api→worker."""
    scan = ScanResult(
        root=".",
        service_hints=[ServiceHint(hint="service_name:api", file="services/api/src/server.ts")],
        external_calls=[
            ExternalCall(target="https://worker.internal.local/rebuild", file="services/api/src/server.ts"),
        ],
    )
    graph = build_service_graph(scan)
    matches = [e for e in graph.edges if e.source == "api" and e.target == "worker"]
    assert len(matches) == 1
    assert matches[0].kind == "http-call"


def test_async_queue_targets_produce_async_queue_edges() -> None:
    """`queue://bullmq/orders` and `queue://kafka/events` produce
    async-queue edges to `bullmq:orders` and `kafka:events`."""
    scan = ScanResult(
        root=".",
        service_hints=[ServiceHint(hint="service_name:worker", file="services/worker/src/index.ts")],
        external_calls=[
            ExternalCall(target="queue://bullmq/orders", file="services/worker/src/index.ts"),
            ExternalCall(target="queue://kafka/events", file="services/worker/src/index.ts"),
        ],
    )
    graph = build_service_graph(scan)
    bullmq_edges = [e for e in graph.edges if e.target == "bullmq:orders"]
    kafka_edges = [e for e in graph.edges if e.target == "kafka:events"]
    assert len(bullmq_edges) == 1
    assert bullmq_edges[0].kind == "async-queue"
    assert len(kafka_edges) == 1
    assert kafka_edges[0].kind == "async-queue"


def test_edges_dedup_by_source_target_and_kind() -> None:
    """Two mentions of the same edge in a scan collapse to one edge in
    the graph. A peer reached both via HTTP and via env-configured URL
    shows up as two edges — different kinds."""
    scan = ScanResult(
        root=".",
        service_hints=[ServiceHint(hint="service_name:api", file="services/api/src/server.ts")],
        external_calls=[
            ExternalCall(target="https://worker.internal.local/a", file="services/api/src/server.ts"),
            ExternalCall(target="https://worker.internal.local/b", file="services/api/src/server.ts"),
            ExternalCall(target="env://WORKER_URL", file="services/api/src/server.ts"),
        ],
    )
    graph = build_service_graph(scan)
    api_to_worker = [e for e in graph.edges if e.source == "api" and e.target == "worker"]
    kinds = {e.kind for e in api_to_worker}
    assert kinds == {"http-call", "env-configured"}
    assert len(api_to_worker) == 2  # http-call once, env-configured once


def test_edges_reach_a_target_without_local_service_source_are_dropped() -> None:
    """If we can't attribute the caller to a known service (no
    services/* prefix, no service_name hint on the file), we don't
    invent one."""
    scan = ScanResult(
        root=".",
        external_calls=[ExternalCall(target="https://worker.internal.local/x", file="src/util.ts")],
    )
    graph = build_service_graph(scan)
    assert graph.edges == []


def test_peers_of_returns_first_seen_ordered_neighbors() -> None:
    scan = ScanResult(
        root=".",
        service_hints=[ServiceHint(hint="service_name:api", file="services/api/src/server.ts")],
        edge_hints=[
            EdgeHint(hint="edge:api->b", file="services/api/src/server.ts"),
            EdgeHint(hint="edge:api->a", file="services/api/src/server.ts"),
            EdgeHint(hint="edge:api->c", file="services/api/src/server.ts"),
            EdgeHint(hint="edge:api->b", file="services/api/src/server.ts"),  # dup
        ],
    )
    graph = build_service_graph(scan)
    assert graph.peers_of("api") == ["b", "a", "c"]


# ---------------------------------------------------------------------------
# End-to-end: the fixture used by test_node_service_analyzer.py mirrors
# the real Bluesky-shaped scans this feature is aimed at.
# ---------------------------------------------------------------------------


def test_realistic_multi_service_scan_produces_expected_topology() -> None:
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/xrpc/ping", method="GET", file="services/api/src/server.ts"),
            Route(path="/internal/rebuild", method="POST", file="services/worker/src/worker.ts"),
        ],
        service_hints=[
            ServiceHint(hint="service_name:api", file="services/api/src/server.ts"),
            ServiceHint(hint="service_name:worker", file="services/worker/src/worker.ts"),
        ],
        auth_hints=[
            AuthHint(hint="service_role:api", file="services/api/src/server.ts"),
            AuthHint(hint="service_role:worker", file="services/worker/src/worker.ts"),
        ],
        edge_hints=[
            EdgeHint(hint="edge:api->worker", file="services/api/src/server.ts"),
        ],
        external_calls=[
            ExternalCall(target="https://worker.internal.local/rebuild", file="services/api/src/server.ts"),
            ExternalCall(target="env://FEEDGEN_URL", file="services/api/src/server.ts"),
        ],
    )
    graph = build_service_graph(scan)

    assert graph.node_names() >= {"api", "worker", "feedgen"}
    api = next(n for n in graph.nodes if n.name == "api")
    worker = next(n for n in graph.nodes if n.name == "worker")
    assert api.role == "api"
    assert worker.role == "worker"

    api_edges = [e for e in graph.edges if e.source == "api"]
    kinds_to_targets: dict[str, set[str]] = {}
    for e in api_edges:
        kinds_to_targets.setdefault(e.kind, set()).add(e.target)
    assert kinds_to_targets["analyzer-declared"] == {"worker"}
    assert kinds_to_targets["http-call"] == {"worker"}
    assert kinds_to_targets["env-configured"] == {"feedgen"}
