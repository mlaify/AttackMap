from __future__ import annotations

import networkx as nx

from .models import ScanResult


def build_graph(scan: ScanResult) -> nx.DiGraph:
    graph = nx.DiGraph()

    graph.add_node("repo", kind="system", label="Repository")

    if scan.routes:
        graph.add_node("web", kind="service", label="Web/API Layer")
        graph.add_edge("repo", "web", relation="contains")

    for db in {d.kind for d in scan.databases}:
        graph.add_node(db, kind="database", label=db)
        graph.add_edge("web" if scan.routes else "repo", db, relation="uses")

    for idx, call in enumerate(scan.external_calls, start=1):
        node_id = f"external_{idx}"
        graph.add_node(node_id, kind="external", label=call.target)
        graph.add_edge("web" if scan.routes else "repo", node_id, relation="calls")

    return graph
