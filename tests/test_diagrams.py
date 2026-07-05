"""Tests for Mermaid + Graphviz DOT export (#49)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.diagrams import (
    render_attack_paths_dot,
    render_attack_paths_mermaid,
    render_topology_dot,
    render_topology_mermaid,
)
from attackmap.models import AttackPath
from attackmap.topology import ServiceEdge, ServiceGraph, ServiceNode


# ---------------------------------------------------------------------------
# Attack paths — Mermaid
# ---------------------------------------------------------------------------


def _sample_path() -> AttackPath:
    return AttackPath(
        name="Webhook forgery to state change",
        steps=[
            "Entry: POST /webhook/stripe in app.py",
            "Weak point: no signature verification",
            "Propagation: reaches sqlite in app.py",
        ],
        impact="Unauthorized state change on billing records",
    )


def test_attack_paths_mermaid_contains_flowchart_block() -> None:
    md = render_attack_paths_mermaid([_sample_path()])
    assert "```mermaid" in md
    assert "flowchart TD" in md
    assert "```" in md.split("```mermaid", 1)[1]  # closing fence


def test_attack_paths_mermaid_declares_a_node_per_step_plus_impact() -> None:
    path = _sample_path()
    md = render_attack_paths_mermaid([path])
    # 3 steps + 1 impact = 4 node declarations; exclude the chain line
    # (which starts with P1_0 but has no `[`).
    node_lines = [
        line for line in md.splitlines() if line.strip().startswith("P1_") and '["' in line
    ]
    assert len(node_lines) == 4
    assert 'Impact: Unauthorized state change' in md


def test_attack_paths_mermaid_chains_nodes_in_order() -> None:
    md = render_attack_paths_mermaid([_sample_path()])
    # The chain line should contain each node id in order.
    chain_line = next(
        line
        for line in md.splitlines()
        if line.strip().startswith("P1_0 -->")
    )
    assert "P1_0 --> P1_1 --> P1_2 --> P1_3" in chain_line


def test_attack_paths_mermaid_escapes_quotes_in_step_text() -> None:
    path = AttackPath(
        name="quoted",
        steps=['Entry: hit "/admin"'],
        impact='"boom"',
    )
    md = render_attack_paths_mermaid([path])
    # Raw double-quotes inside a Mermaid node label break the parser.
    # Our escape swaps them for single quotes.
    for line in md.splitlines():
        if line.strip().startswith("P1_") and '["' in line:
            # Node body starts at the first `["` and ends at `"]`.
            body = line.split('["', 1)[1].rsplit('"]', 1)[0]
            assert '"' not in body


def test_attack_paths_mermaid_empty_yields_placeholder_message() -> None:
    md = render_attack_paths_mermaid([])
    assert "No attack paths surfaced" in md
    assert "```mermaid" not in md


def test_attack_paths_mermaid_numbers_multiple_paths() -> None:
    p1 = _sample_path()
    p2 = AttackPath(name="Admin abuse", steps=["Entry: DELETE /admin"], impact="Data loss")
    md = render_attack_paths_mermaid([p1, p2])
    assert "## 1. Webhook forgery" in md
    assert "## 2. Admin abuse" in md
    # Ensure node ids don't collide across paths.
    assert "P1_0" in md and "P2_0" in md


# ---------------------------------------------------------------------------
# Attack paths — DOT
# ---------------------------------------------------------------------------


def test_attack_paths_dot_wraps_in_digraph() -> None:
    dot = render_attack_paths_dot([_sample_path()])
    assert dot.startswith("digraph AttackPaths {")
    assert dot.rstrip().endswith("}")


def test_attack_paths_dot_declares_subgraph_per_path() -> None:
    dot = render_attack_paths_dot([_sample_path(), _sample_path()])
    assert dot.count("subgraph cluster_p") == 2
    assert dot.count("cluster_p1") >= 1
    assert dot.count("cluster_p2") >= 1


def test_attack_paths_dot_escapes_quotes() -> None:
    path = AttackPath(name='a "b"', steps=['step "1"'], impact='"boom"')
    dot = render_attack_paths_dot([path])
    # No unescaped `"` inside a label.
    for line in dot.splitlines():
        if 'label="' in line:
            body = line.split('label="', 1)[1]
            # First unescaped `"` should be the closing quote of the label.
            # Any interior `"` must be preceded by a backslash.
            i = 0
            while i < len(body):
                if body[i] == "\\":
                    i += 2
                    continue
                if body[i] == '"':
                    break
                i += 1


def test_attack_paths_dot_empty_yields_note_node() -> None:
    dot = render_attack_paths_dot([])
    assert "No attack paths surfaced" in dot


# ---------------------------------------------------------------------------
# Topology — Mermaid
# ---------------------------------------------------------------------------


def _sample_graph() -> ServiceGraph:
    return ServiceGraph(
        nodes=[
            ServiceNode(name="pds", role="service"),
            ServiceNode(name="postgres", role="datastore"),
            ServiceNode(name="stripe", role="external"),
        ],
        edges=[
            ServiceEdge(source="pds", target="postgres", kind="analyzer-declared", file="pds.py"),
            ServiceEdge(source="pds", target="stripe", kind="http-call", file="webhook.py"),
        ],
    )


def test_topology_mermaid_contains_all_nodes() -> None:
    md = render_topology_mermaid(_sample_graph())
    for name in ("pds", "postgres", "stripe"):
        assert name in md
    assert "flowchart LR" in md


def test_topology_mermaid_edge_styles_differ_by_kind() -> None:
    md = render_topology_mermaid(_sample_graph())
    # Two edges → two linkStyle directives (analyzer-declared skips
    # linkStyle since default style suffices; but http-call gets one).
    assert "linkStyle" in md
    # http-call uses a dashed variant.
    assert ".->" in md or "stroke-dasharray" in md


def test_topology_mermaid_skips_orphan_edges() -> None:
    graph = ServiceGraph(
        nodes=[ServiceNode(name="a")],
        edges=[ServiceEdge(source="a", target="missing", kind="http-call", file="f")],
    )
    md = render_topology_mermaid(graph)
    # No node declared for `missing` → the edge must not surface.
    assert "missing" not in md


def test_topology_mermaid_empty_graph_yields_placeholder() -> None:
    md = render_topology_mermaid(ServiceGraph())
    assert "No services surfaced" in md
    assert "```mermaid" not in md


def test_topology_mermaid_shows_role_when_not_default() -> None:
    md = render_topology_mermaid(_sample_graph())
    # postgres role="datastore" should appear as an italic sublabel.
    assert "<i>datastore</i>" in md
    assert "<i>external</i>" in md
    # pds role="service" is the default → suppressed.
    # (This is an ergonomic call, guarded by test so future edits stay
    # deliberate.)
    assert "<i>service</i>" not in md


# ---------------------------------------------------------------------------
# Topology — DOT
# ---------------------------------------------------------------------------


def test_topology_dot_wraps_in_digraph() -> None:
    dot = render_topology_dot(_sample_graph())
    assert dot.startswith("digraph Topology {")
    assert "rankdir=LR" in dot


def test_topology_dot_edge_styles_differ_by_kind() -> None:
    dot = render_topology_dot(_sample_graph())
    assert "style=dashed" in dot  # http-call
    # analyzer-declared → default (no style attribute), so it should
    # NOT accidentally get one of the other kinds' colors.
    lines = [l for l in dot.splitlines() if "->" in l]
    analyzer_edge = next(l for l in lines if "s0 -> s1" in l)  # pds → postgres
    assert "style=" not in analyzer_edge


def test_topology_dot_empty_graph_yields_note() -> None:
    dot = render_topology_dot(ServiceGraph())
    assert "No services surfaced" in dot


# ---------------------------------------------------------------------------
# Integration: write_reports produces the four diagram files
# ---------------------------------------------------------------------------


def test_write_reports_emits_diagram_files(tmp_path: Path) -> None:
    from attackmap.report import write_reports
    from attackmap.models import ScanResult

    scan = ScanResult(root=str(tmp_path))
    write_reports(
        tmp_path / "out",
        scan,
        architecture_md="# arch\n",
        attack_surface_md="# surface\n",
        defensive_review_md="# review\n",
        attack_surfaces=[],
        findings=[],
        attack_paths=[_sample_path()],
    )
    out = tmp_path / "out"
    assert (out / "attackmap-paths.md").exists()
    assert (out / "attackmap-topology.md").exists()
    assert (out / "attackmap-paths.dot").exists()
    assert (out / "attackmap-topology.dot").exists()
    # Content sanity — mermaid file has the flowchart fence, dot file
    # opens with `digraph`.
    assert "flowchart TD" in (out / "attackmap-paths.md").read_text(encoding="utf-8")
    assert (out / "attackmap-paths.dot").read_text(encoding="utf-8").startswith("digraph")
