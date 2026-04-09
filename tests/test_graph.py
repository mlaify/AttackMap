from attackmap.graph import build_graph
from attackmap.models import DatabaseHint, Route, ScanResult


def test_build_graph_creates_web_and_db_nodes() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/users", method="GET", file="api.py")],
        databases=[DatabaseHint(kind="postgresql", file="db.py")],
    )

    graph = build_graph(scan)

    assert "web" in graph.nodes
    assert "postgresql" in graph.nodes
    assert graph.has_edge("web", "postgresql")
